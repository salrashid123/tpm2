package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
	cPub            = "childPub.bin"
	cPriv           = "childPriv.bin"
	gPub            = "grandchildPub.bin"
	gPriv           = "grandchildPriv.bin"
	encryptedData   = "encrypteddata.bin"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	mode  = flag.String("mode", "create", "import or create or load")
	flush = flag.String("flush", "all", "Flush handles to HMAC")

	dataToSign = []byte("secret")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	primaryTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		AuthPolicy: []byte(defaultPassword),
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	childTepmplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
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

	grandchildTemplate = tpm2.Public{
		Type:    tpm2.AlgSymCipher,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		SymCipherParameters: &tpm2.SymCipherParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
		},
	}

	// for RSA keys
	grandchildTemplateRSA = tpm2.Public{
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

	pcrSelection := tpm2.PCRSelection{}

	if *mode == "create" {
		fmt.Printf("======= CreatePrimary ========\n")
		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, primaryTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, pkh)

		fmt.Printf("======= Create Child ========\n")
		childpriv, childpub, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, childTepmplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
			os.Exit(1)
		}
		childHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, childpub, childpriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading  key %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, childHandle)

		err = ioutil.WriteFile(cPub, childpub, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childPub failed for childFile%v\n", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(cPriv, childpriv, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		fmt.Printf("======= Create GrandChild ========\n")

		//grandchildpriv, grandchildpub, _, _, _, err := tpm2.CreateKey(rwc, childHandle, pcrSelection, defaultPassword, defaultPassword, grandchildTemplateRSA)
		grandchildpriv, grandchildpub, _, _, _, err := tpm2.CreateKey(rwc, childHandle, pcrSelection, defaultPassword, defaultPassword, grandchildTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
			os.Exit(1)
		}
		grandchildHandle, _, err := tpm2.Load(rwc, childHandle, defaultPassword, grandchildpub, grandchildpriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading  key %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, grandchildHandle)

		err = ioutil.WriteFile(gPub, grandchildpub, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grandchildpub failed for childFile%v\n", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(gPriv, grandchildpriv, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grandchildpriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		// fmt.Printf("======= Encrypt with GrandChild ========\n")
		data := []byte("foooo")
		iv := bytes.Repeat([]byte("a"), 16)
		encrypted, err := tpm2.EncryptSymmetric(rwc, emptyPassword, grandchildHandle, iv, data)
		if err != nil {
			log.Fatalf("EncryptSymmetric failed: %s", err)
		}
		log.Printf("Encrypted %s", base64.StdEncoding.EncodeToString(encrypted))

		err = ioutil.WriteFile(encryptedData, encrypted, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grandchildpriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		decrypted, err := tpm2.DecryptSymmetric(rwc, emptyPassword, grandchildHandle, iv, encrypted)
		if err != nil {
			log.Fatalf("DecryptSymmetric failed: %s", err)
		}

		log.Printf("decrypted %s\n", decrypted)

		// fmt.Printf("======= RSA ========\n")
		// for RSA grandchild
		// khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSign, tpm2.HandleOwner)
		// if err != nil {
		// 	log.Fatalf("Hash failed unexpectedly: %v", err)
		// 	return
		// }

		// sig, err := tpm2.Sign(rwc, grandchildHandle, emptyPassword, khDigest[:], khValidation, &tpm2.SigScheme{
		// 	Alg:  tpm2.AlgRSASSA,
		// 	Hash: tpm2.AlgSHA256,
		// })
		// if err != nil {
		// 	log.Fatalf("Error Signing: %v", err)
		// }

		// log.Printf("Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

	}

	if *mode == "load" {
		fmt.Printf("======= LoadPrimary ========\n")

		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, primaryTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, pkh)

		fmt.Printf("======= LoadChild ========\n")

		childpub, err := ioutil.ReadFile(cPub)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}
		childpriv, err := ioutil.ReadFile(cPriv)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		childHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, childpub, childpriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading  key %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, childHandle)
		fmt.Printf("======= LoadGrandChild ========\n")

		grandchildpub, err := ioutil.ReadFile(gPub)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}
		grandchildpriv, err := ioutil.ReadFile(gPriv)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		gcH, _, err := tpm2.Load(rwc, childHandle, defaultPassword, grandchildpub, grandchildpriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading  key %v\n", err)
			os.Exit(1)
		}

		defer tpm2.FlushContext(rwc, gcH)

		fmt.Printf("======= Decrypt ========\n")

		encrypted, err := ioutil.ReadFile(encryptedData)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		decrypted, err := tpm2.DecryptSymmetric(rwc, emptyPassword, gcH, iv, encrypted)
		if err != nil {
			log.Fatalf("DecryptSymmetric failed: %s", err)
		}

		log.Printf("decrypted %s\n", decrypted)

		// fmt.Printf("======= Sign ========\n")
		// for RSA key using go-tpm-tools
		/// init Key

		// kk, err := client.NewCachedKey(rwc, tpm2.HandleOwner, grandchildTemplate, gcH)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "can't load cached key %q: %v", *tpmPath, err)
		// 	os.Exit(1)
		// }
		// s, err := kk.SignData(dataToSign)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "can't seal %q: %v", *tpmPath, err)
		// 	os.Exit(1)
		// }

		// log.Printf("Signature data:  %s", base64.RawStdEncoding.EncodeToString(s))

	}

}
