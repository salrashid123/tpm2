package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"log"
	"os"

	// "github.com/google/go-tpm-tools/simulator"
	// "github.com/google/go-tpm/tpmutil"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath    = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	out        = flag.String("out", "private.pem", "privateKey File")
	dataToSign = flag.String("datatosign", "foo", "data to sign")
)

func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	//rwc, err := tpmutil.OpenTPM(*tpmPath)
	rwc, err := simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary ========")

	data := []byte(*dataToSign)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", base64.StdEncoding.EncodeToString(primaryKey.Name.Buffer))

	// rsa

	log.Printf("======= create key  ========")

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
		AuthPolicy: tpm2.TPM2BDigest{},
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

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	// *************** evict

	// https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-3.1.8
	// _, err = tpm2.EvictControl{
	// 	Auth: tpm2.TPMRHOwner,
	// 	ObjectHandle: &tpm2.NamedHandle{
	// 		Handle: primaryKey.ObjectHandle,
	// 		Name:   primaryKey.Name,
	// 	},
	// 	PersistentHandle: tpm2.TPMHandle(*persistenthandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create rsa %v", err)
	// }

	/// ============================ =================================================================================================

	// write the key to file
	log.Printf("======= writing key to file ========")

	//tkf, err := keyfile.NewLoadableKey(rsaKeyResponse.OutPublic, rsaKeyResponse.OutPrivate, tpm2.TPMHandle(*persistenthandle), false)
	tkf, err := keyfile.NewLoadableKey(rsaKeyResponse.OutPublic, rsaKeyResponse.OutPrivate, primaryKey.ObjectHandle, false)
	if err != nil {
		log.Fatalf("failed to create KeyFile: %v", err)
	}

	b := new(bytes.Buffer)

	err = keyfile.Encode(b, tkf)
	if err != nil {
		log.Fatalf("failed to encode Key: %v", err)
	}

	log.Printf("rsa Key PEM: \n%s\n", b)

	err = os.WriteFile(*out, b.Bytes(), 0644)
	if err != nil {
		log.Fatalf("failed to write private key to file %v", err)
	}

	/// ============================ =================================================================================================

	log.Printf("======= generate test signature with RSA key ========")
	digest := sha256.Sum256(data)

	// objAuth := &tpm2.TPM2BAuth{
	// 	Buffer: rsaPassword,
	// }

	rspSign, err := tpm2.Sign{
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
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	pubKey, err := tkf.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	rsaPub := pubKey.(*rsa.PublicKey)
	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	log.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: rsaKeyResponse.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	rwc.Close()

	/// now rerun the test...but this time load the private key from disk
	log.Printf("======= reopening TPM ========")
	// ===============================================================================================================================
	//rwc, err = tpmutil.OpenTPM(*tpmPath)
	rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}

	rwr = transport.FromReadWriter(rwc)
	log.Printf("======= regenerating primary ========")
	// now recreate everything from scratch
	regenPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	log.Printf("regenerated primary key name %s\n", base64.StdEncoding.EncodeToString(regenPrimary.Name.Buffer))

	// load the rsa key from disk
	log.Printf("======= reading key from file ========")
	c, err := os.ReadFile(*out)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	log.Printf("======= reloading key from file ========")

	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: regenPrimary.ObjectHandle,
			Name:   tpm2.TPM2BName(regenPrimary.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load rsa key: %v", err)
	}

	flush := tpm2.FlushContext{
		FlushHandle: regenPrimary.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close primary  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close rsa key handle: %v", err)
		}
	}()

	// now try to create a signature using a go-tpm-tools.client.Key
	log.Printf("======= constructing handle for go-tpm-tools.client.Key========")

	// note, go-tpm-tools uses the legacy go-tpm library so its a bit awkward
	pHandle := tpmutil.Handle(regenRSAKey.ObjectHandle.HandleValue())

	k, err := client.LoadCachedKey(rwc, pHandle, nil)
	if err != nil {
		log.Fatalf("error loading rsa key%v\n", err)
	}

	r, err := k.GetSigner()
	if err != nil {
		log.Fatalf("Error getting singer %v\n", err)
	}

	s, err := r.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("Error signing %v\n", err)
	}
	log.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

}
