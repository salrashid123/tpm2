package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
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
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
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

	pcrList := []int{0}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, pkh)

	pkhBytes, err := tpm2.ContextSave(rwc, pkh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for pkh %v\n", err)
		os.Exit(1)
	}

	// err = tpm2.FlushContext(rwc, pkh)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
	// 	os.Exit(1)
	// }
	err = ioutil.WriteFile(*primaryHandle, pkhBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
		os.Exit(1)
	}

	// pkh, err = tpm2.ContextLoad(rwc, pkhBytes)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "ContextLoad failed for pkh %v\n", err)
	// 	os.Exit(1)
	// }

	privInternal, pubArea, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, rsaKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
		os.Exit(1)
	}
	newHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, newHandle)

	ekhBytes, err := tpm2.ContextSave(rwc, newHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for ekh %v\n", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(*keyHandle, ekhBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for ekh%v\n", err)
		os.Exit(1)
	}

	// pHandle := tpmutil.Handle(0x81010002)
	// err = tpm2.EvictControl(rwc, defaultPassword, tpm2.HandleOwner, newHandle, pHandle)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error  persisting hash key  %v\n", err)
	// 	os.Exit(1)
	// }
	// defer tpm2.FlushContext(rwc, pHandle)

	fmt.Printf("======= Key persisted ========\n")

	fmt.Printf("======= Sign with new RSA ========\n")
	dataToSeal := []byte("secret")

	digest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSeal, tpm2.HandleOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hash failed unexpectedly: %v", err)
		return
	}

	sig, err := tpm2.Sign(rwc, newHandle, "", digest[:], khValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Signing: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Signature data:  %s\n", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

	utPub, err := tpm2.DecodePublic(pubArea)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error DecodePublic AK %v", utPub)
		return
	}

	uap, err := utPub.Key()
	if err != nil {
		fmt.Fprintf(os.Stderr, "akPub.Key() failed: %s", err)
		return
	}
	uBytes, err := x509.MarshalPKIXPublicKey(uap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to convert akPub: %v", err)
		return
	}

	uakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: uBytes,
		},
	)
	fmt.Printf("RSA Signing Key \n%s\n", string(uakPubPEM))
	hsh := crypto.SHA256.New()
	hsh.Write(dataToSeal)
	block, _ := pem.Decode(uakPubPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Unable to decode akPubPEM %v", err)
		return
	}

	r, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create rsa Key from PEM %v", err)
		return
	}
	rsaPub := *r.(*rsa.PublicKey)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sig.RSA.Signature); err != nil {
		fmt.Fprintf(os.Stderr, "VerifyPKCS1v15 failed: %v", err)
	}
	fmt.Printf("signature Verified\n")
}
