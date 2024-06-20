package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	//tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	tpmPath        = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	mode           = flag.String("mode", "create", "import or create or load")
	childTepmplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			Decrypt:             true,
			Restricted:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
				},
			},
		),
	}

	grandchildTepmplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			Decrypt:             true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
				},
			},
		),
	}
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	if *mode == "create" {

		log.Printf("======= createPrimary ========")

		cmdPrimary := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		}
		if err != nil {
			log.Fatalf("Error creating primary: %v", err)
		}

		cPrimary, err := cmdPrimary.Execute(rwr)
		if err != nil {
			log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
		}

		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		log.Printf("======= create child ========")
		cCreate, err := tpm2.Create{
			ParentHandle: tpm2.NamedHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
			},
			InPublic: tpm2.New2B(childTepmplate),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
		}

		err = os.WriteFile("child.pub", cCreate.OutPublic.Bytes(), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childPub failed for childFile%v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile("child.priv", cCreate.OutPrivate.Buffer, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		aesKey1, err := tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
			},
			InPrivate: cCreate.OutPrivate,
			InPublic:  cCreate.OutPublic,
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't load object %q: %v", *tpmPath, err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: aesKey1.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
		}()

		log.Printf("======= create grandchild ========")
		gcCreate, err := tpm2.Create{
			ParentHandle: tpm2.NamedHandle{
				Handle: aesKey1.ObjectHandle,
				Name:   aesKey1.Name,
			},
			InPublic: tpm2.New2B(grandchildTepmplate),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
		}

		err = os.WriteFile("grandchild.pub", gcCreate.OutPublic.Bytes(), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childPub failed for childFile%v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile("grandchild.priv", gcCreate.OutPrivate.Buffer, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		gcaesKey, err := tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: aesKey1.ObjectHandle,
				Name:   aesKey1.Name,
			},
			InPrivate: gcCreate.OutPrivate,
			InPublic:  gcCreate.OutPublic,
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't load object %q: %v", *tpmPath, err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: gcaesKey.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
		}()

		data := []byte("foooo")

		iv := make([]byte, aes.BlockSize)
		_, err = io.ReadFull(rand.Reader, iv)
		if err != nil {
			log.Fatalf("can't read rsa details %q: %v", *tpmPath, err)
		}

		keyAuth := tpm2.AuthHandle{
			Handle: gcaesKey.ObjectHandle,
			Name:   gcaesKey.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		}
		encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, false)

		if err != nil {
			log.Fatalf("EncryptSymmetric failed: %s", err)
		}
		log.Printf("IV: %s", hex.EncodeToString(iv))
		log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

		decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, encrypted, true)
		if err != nil {
			log.Fatalf("EncryptSymmetric failed: %s", err)
		}

		log.Printf("Decrypted %s", string(decrypted))

	}
	if *mode == "load" {

		log.Printf("======= createPrimary ========")

		cmdPrimary := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		}
		if err != nil {
			log.Fatalf("Error creating primary: %v", err)
		}

		cPrimary, err := cmdPrimary.Execute(rwr)
		if err != nil {
			log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
		}

		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		childpub, err := os.ReadFile("child.pub")
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}
		childpriv, err := os.ReadFile("child.priv")
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		grandchildpub, err := os.ReadFile("grandchild.pub")
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}
		grandchildpriv, err := os.ReadFile("grandchild.priv")
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		aesKey1, err := tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
			},
			InPrivate: tpm2.TPM2BPrivate{
				Buffer: childpriv,
			},
			InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](childpub),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't load object %q: %v", *tpmPath, err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: aesKey1.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
		}()

		gcaesKey, err := tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: aesKey1.ObjectHandle,
				Name:   aesKey1.Name,
			},
			InPrivate: tpm2.TPM2BPrivate{
				Buffer: grandchildpriv,
			},
			InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](grandchildpub),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't load object %q: %v", *tpmPath, err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: gcaesKey.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
		}()

		data := []byte("foooo")

		iv := make([]byte, aes.BlockSize)
		_, err = io.ReadFull(rand.Reader, iv)
		if err != nil {
			log.Fatalf("can't read rsa details %q: %v", *tpmPath, err)
		}

		keyAuth := tpm2.AuthHandle{
			Handle: gcaesKey.ObjectHandle,
			Name:   gcaesKey.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		}
		encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, false)

		if err != nil {
			log.Fatalf("EncryptSymmetric failed: %s", err)
		}
		log.Printf("IV: %s", hex.EncodeToString(iv))
		log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

		decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, encrypted, true)
		if err != nil {
			log.Fatalf("EncryptSymmetric failed: %s", err)
		}

		log.Printf("Decrypted %s", string(decrypted))

	}

}

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCFB,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}
