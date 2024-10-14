package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"

	// "github.com/google/go-tpm-tools/simulator"
	// "github.com/google/go-tpm/tpmutil"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	out              = flag.String("out", "private.pem", "privateKey File")
	pcrBank          = flag.Uint("pcrbank", 23, "PCR to use")
	dataToSign       = flag.String("datatosign", "foo", "data to sign")
	persistenthandle = flag.Uint("persistenthandle", 0x81000000, "persistent Handle to save key to")

	primaryTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get() //GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

type TPM struct {
	transport io.ReadWriteCloser
}

func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

func getTPM(s io.ReadWriteCloser) (transport.TPMCloser, error) {
	return &TPM{

		transport: s,
	}, nil
}

func (t *TPM) Close() error {
	return t.transport.Close()
}

func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary ========")

	data := []byte(*dataToSign)
	primaryPassword := []byte("")
	primarySensitive := []byte("some sensitive data")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		//InPublic:      tpm2.New2B(primaryTemplate),
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),

		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: primaryPassword,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: primarySensitive,
				}),
			},
		},
	}

	primaryKey, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", hex.EncodeToString(primaryKey.Name.Buffer))
	log.Printf("primaryKey handle Value %d\n", cmdPrimary.PrimaryHandle.HandleValue())

	// rsa

	log.Printf("======= create key with PCRpolicy ========")
	policy, err := pcrPolicyDigest(rwr, []uint{*pcrBank})
	if err != nil {
		log.Fatalf("can't create policy digest %q: %v", *tpmPath, err)
	}

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	rsaKeyRequest := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(primaryPassword),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}
	rsaKeyResponse, err := rsaKeyRequest.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	// *************** evict

	// https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-3.1.8
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: tpm2.TPMHandle(*persistenthandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	/// ============================ =================================================================================================

	tkf, err := keyfile.NewLoadableKey(rsaKeyResponse.OutPublic, rsaKeyResponse.OutPrivate, tpm2.TPMHandle(*persistenthandle), true)
	if err != nil {
		log.Fatalf("failed to create KeyFile: %v", err)
	}

	b, err := keyfile.Encode(tkf)
	if err != nil {
		log.Fatalf("failed to encode Key: %v", err)
	}

	log.Printf("rsa Key PEM: \n%s\n", b)

	err = os.WriteFile(*out, b, 0644)
	if err != nil {
		log.Fatalf("failed to write private key to file %v", err)
	}

	/// ============================ =================================================================================================

	log.Printf("======= generate test signature with RSA key ========")
	digest := sha256.Sum256(data)

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	pub, err := rsaKeyResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	log.Printf("signature: %s\n", hex.EncodeToString(rsassa.Sig.Buffer))

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: rsaKeyResponse.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	rwc.Close()

	/// now rerun the test...but this time load the private key from disk

	// ===============================================================================================================================
	rwc, err = tpmutil.OpenTPM(*tpmPath)
	//rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}

	rwr = transport.FromReadWriter(rwc)

	// now recreate everything from scratch
	cmdPrimary2 := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		//InPublic:      tpm2.New2B(primaryTemplate),
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),

		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: primaryPassword,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: primarySensitive,
				}),
			},
		},
	}

	primary2, err := cmdPrimary2.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	log.Printf("regenerated primary key name %s\n", hex.EncodeToString(primary2.Name.Buffer))

	c, err := os.ReadFile(*out)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	rsaKey2Load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary2.ObjectHandle,
			Name:   tpm2.TPM2BName(primary2.Name),
			Auth:   tpm2.PasswordAuth(primaryPassword),
		},

		InPublic:  tpm2.New2B(key.Pubkey),
		InPrivate: key.Privkey,
	}
	rsaKey2, err := rsaKey2Load.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load rsa key: %v", err)
	}

	flush := tpm2.FlushContext{
		FlushHandle: primary2.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close primary  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKey2.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close rsa key handle: %v", err)
		}
	}()

	// newobjAuth := &tpm2.TPM2BAuth{
	// 	Buffer: keyPassword,
	// }

	sign2 := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: rsaKey2.ObjectHandle,
			Name:   rsaKey2.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign2, err := sign2.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	rsassa2, err := rspSign2.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part public: %v", err)
	}

	log.Printf("signature: %s\n", hex.EncodeToString(rsassa2.Sig.Buffer))

}

func pcrPolicyDigest(thetpm transport.TPM, pcr []uint) ([]byte, error) {
	sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcr...),
				},
			},
		},
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	return pgd.PolicyDigest.Buffer, nil
}

func must2BPrivate(data []byte) tpm2.TPM2BPrivate {
	return tpm2.TPM2BPrivate{
		Buffer: data,
	}
}
