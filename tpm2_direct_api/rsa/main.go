package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	parentPassword = ""
	ownerPassword  = ""
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	publicFile       = flag.String("publicFile", "new-parent.pub", "New Parent public")
	privateFile      = flag.String("privateFile", "new-parent.priv", "New Parent private")

	primaryTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
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
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
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
	log.Println("======= Init  ========")

	rwc, err := tpmutil.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary ========")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTemplate),
		CreationPCR: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		},
	}
	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
	}

	cPrimary, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err := flush.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	log.Printf("Name %s\n", hex.EncodeToString(cPrimary.Name.Buffer))

	log.Printf("======= create ========")
	cmdCreate := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(rsaTemplate),
	}

	cCreate, err := cmdCreate.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}

	loadCmd := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}
	loadRsp, err := loadCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadRsp.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	pub, err := cCreate.OutPublic.Contents()
	if err != nil {
		log.Fatalf("can't read public object %q: %v", *tpmPath, err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("can't read rsa details %q: %v", *tpmPath, err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		log.Fatalf("can't read public unique %q: %v", *tpmPath, err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("can't read rsapub unique %q: %v", *tpmPath, err)
	}

	b, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		log.Fatalf("Unable to convert akpub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	log.Printf("akPub: \n%v", string(akPubPEM))

	err = os.WriteFile(*publicFile, cCreate.OutPublic.Bytes(), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "childPub failed for childFile%v\n", err)
		os.Exit(1)
	}
	err = os.WriteFile(*privateFile, cCreate.OutPrivate.Buffer, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "childriv failed for childFile%v\n", err)
		os.Exit(1)
	}

	// evict control
	// _, err = tpm2.EvictControl{
	// 	Auth: tpm2.TPMRHOwner,
	// 	ObjectHandle: &tpm2.NamedHandle{
	// 		Handle: loadRsp.ObjectHandle,
	// 		Name:   loadRsp.Name,
	// 	},
	// 	PersistentHandle: 0x81000000,
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't childPub failed for write%v\n", err)
	// }

	message := []byte("secret")

	encryptCmd := tpm2.RSAEncrypt{
		KeyHandle: loadRsp.ObjectHandle,
		Message:   tpm2.TPM2BPublicKeyRSA{Buffer: message},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}
	encryptRsp, err := encryptCmd.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt  failed for %v\n", err)
		os.Exit(1)
	}

	decryptCmd := tpm2.RSADecrypt{
		KeyHandle:  loadRsp.ObjectHandle,
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: encryptRsp.OutData.Buffer},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}
	decryptRsp, err := decryptCmd.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt  failed for %v\n", err)
		os.Exit(1)
	}

	if !bytes.Equal(message, decryptRsp.Message.Buffer) {

		fmt.Fprintf(os.Stderr, "want %x got %x", message, decryptRsp.Message.Buffer)
		os.Exit(1)
	}
}
