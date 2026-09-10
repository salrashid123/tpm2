package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const ()

var (
	ekPubFile           = flag.String("ekPubFile", "output/ekpub.pem", "file to write the ekpub")
	akPubFile           = flag.String("akPubFile", "output/akpub.pem", "file to write the akpub")
	secret              = flag.String("secret", "somerandomsecret", "secret")
	credentialBlobFile  = flag.String("credentialBlobFile", "output/credentialblob.bin", "Credential Blob File")
	encryptedSecretFile = flag.String("encryptedSecret", "output/encryptedSecret.bin", "encryptedSecret Blob File")

	RSAAKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
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
)

func main() {
	flag.Parse()

	ep, err := os.ReadFile(*ekPubFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	block, _ := pem.Decode(ep)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return
	}
	rsaPub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error converting encryptingPublicKey to rsa")
		return
	}

	ekPububFromPEMTemplate := tpm2.RSAEKTemplate

	ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPub.N.Bytes(),
		},
	)

	ap, err := os.ReadFile(*akPubFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	blockA, _ := pem.Decode(ap)
	parsedKeyA, err := x509.ParsePKIXPublicKey(blockA.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing ak public key : %v", err)
		return
	}
	rsaPubA, ok := parsedKeyA.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error converting ak to rsa")
		return
	}

	RSAAKTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPubA.N.Bytes(),
		},
	)
	sim, err := simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}
	defer sim.Close()
	rwrs := transport.FromReadWriter(sim)
	loadedEk, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
	}.Execute(rwrs)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}
	log.Printf("key Primary Name: %v\n", hex.EncodeToString(loadedEk.Name.Buffer))

	loadedAK, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.New2B(RSAAKTemplate),
	}.Execute(rwrs)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}

	log.Printf("key Name: %v\n", hex.EncodeToString(loadedAK.Name.Buffer))

	secret := tpm2.TPM2BDigest{Buffer: []byte(*secret)}

	mc, err := tpm2.MakeCredential{
		Handle:     loadedEk.ObjectHandle,
		Credential: secret,
		ObjectName: loadedAK.Name,
	}.Execute(rwrs)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}

	log.Printf("CredentialBLob %s\n", hex.EncodeToString(mc.CredentialBlob.Buffer))
	err = os.WriteFile(*credentialBlobFile, mc.CredentialBlob.Buffer, 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*encryptedSecretFile, mc.Secret.Buffer, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
