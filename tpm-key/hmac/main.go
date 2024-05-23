package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"log"
	"os"

	// "github.com/google/go-tpm-tools/simulator"
	// "github.com/google/go-tpm/tpmutil"

	"github.com/foxboron/go-tpm-keyfiles/keyfile"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	out     = flag.String("out", "private.pem", "privateKey File")

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

	rsaTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Decrypt:             true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
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

func main() {
	flag.Parse()

	flag.Parse()
	log.Println("======= Init  ========")

	// ************************

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

	data := []byte("foo")
	primaryPassword := []byte("hello")
	primarySensitive := []byte("ddd")
	keyPassword := []byte("hello2")

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
	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
	}

	primaryKey, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", hex.EncodeToString(primaryKey.Name.Buffer))
	log.Printf("primaryKey handle Value %d\n", cmdPrimary.PrimaryHandle.HandleValue())

	// hmac

	policy, err := pcrPolicyDigest(rwr, []uint{23})
	if err != nil {
		log.Fatalf("can't create policy digest %q: %v", *tpmPath, err)
	}
	hmacTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						}),
				},
			}),
	}

	hmacKeyRequest := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(primaryPassword),
		},
		InPublic: tpm2.New2BTemplate(&hmacTemplate),
	}
	hmacKey, err := hmacKeyRequest.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create hmacKey %q: %v", *tpmPath, err)
	}

	/// ============================ =================================================================================================

	tkf, err := keyfile.NewLoadableKey(hmacKey.OutPublic, hmacKey.OutPrivate, primaryKey.ObjectHandle, false)
	if err != nil {
		log.Fatalf("failed to load hmacKey: %v", err)
	}

	b, err := keyfile.Encode(tkf)
	if err != nil {
		log.Fatalf("failed encoding hmacKey: %v", err)
	}

	log.Printf("hmac Key PEM: \n%s\n", b)

	err = os.WriteFile(*out, b, 0644)
	if err != nil {
		log.Fatalf("failed to write private key to file", err)
	}

	/// ============================ =================================================================================================

	objAuth := &tpm2.TPM2BAuth{
		Buffer: keyPassword,
	}
	hmacBytes, err := hmac(rwr, data, hmacKey.ObjectHandle, hmacKey.Name, *objAuth)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	log.Printf("Hmac: %s\n", base64.StdEncoding.EncodeToString(hmacBytes))

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: hmacKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	rwc.Close()

	// ===============================================================================================================================
	//rwc, err = tpmutil.OpenTPM(*tpmPath)
	rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}

	rwr = transport.FromReadWriter(rwc)

	/// ============================ =================================================================================================

	// now recreate everything from scratch and use the hmac key's by values
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

	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
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

	hmacKey2Load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary2.ObjectHandle,
			Name:   tpm2.TPM2BName(primary2.Name),
			Auth:   tpm2.PasswordAuth(primaryPassword),
		},

		InPublic:  tpm2.New2B(key.Pubkey),
		InPrivate: key.Privkey,
	}
	hmacKey2, err := hmacKey2Load.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create  hmacKey2: %v", err)
	}

	flush := tpm2.FlushContext{
		FlushHandle: primary2.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close TPM hmackey2  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey2.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close hmackey2 handle: %v", err)
		}
	}()

	newobjAuth := &tpm2.TPM2BAuth{
		Buffer: keyPassword,
	}

	d, err := hmac(rwr, data, hmacKey2.ObjectHandle, hmacKey2.Name, *newobjAuth)
	if err != nil {
		log.Fatalf("start hmac session %q: %v", *tpmPath, err)
	}

	log.Printf("recalculated hmac:  %s\n", base64.StdEncoding.EncodeToString(d))

}
