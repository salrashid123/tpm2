package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/client"
	//"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	primaryHandle = flag.String("primaryHandle", "primary.bin", "Handle to the primary")
	keyHandle     = flag.String("keyHandle", "key.bin", "Handle to the privateKey")
	flush         = flag.String("flush", "all", "Flush existing handles")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Printf("error getting handles %s %v", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
				os.Exit(1)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	defer rwc.Close()

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		fmt.Printf("Error getting ek %v", err)
	}
	defer ek.Close()

	ekbytes, err := x509.MarshalPKIXPublicKey(ek.PublicKey())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshall ek: %v", err)
		os.Exit(1)
	}
	ekpem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekbytes,
		},
	)
	fmt.Printf("client.EndorsementKeyRSA \n%s\n", ekpem)

	gceak, err := client.GceAttestationKeyRSA(rwc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read ak : %v", err)
		os.Exit(1)
	}
	defer gceak.Close()
	gceakbytes, err := x509.MarshalPKIXPublicKey(gceak.PublicKey())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshall ek : %v", err)
		os.Exit(1)
	}
	gceakpem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: gceakbytes,
		},
	)
	fmt.Printf("client.GceAttestationKeyRSA \n%s\n", gceakpem)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read ak : %v", err)
		os.Exit(1)
	}
	defer ak.Close()
	akbytes, err := x509.MarshalPKIXPublicKey(ak.PublicKey())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshall ek : %v", err)
		os.Exit(1)
	}
	akpem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akbytes,
		},
	)
	fmt.Printf("client.AttestationKeyRSA \n%s\n", akpem)
}
