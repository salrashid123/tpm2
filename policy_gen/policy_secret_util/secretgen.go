package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	util "github.com/salrashid123/tpm2genkey/util"
)

const (
	pcr = 23
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
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

	log.Printf("======= createPrimary ========")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
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

	log.Printf("======= create ========")

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		cleanup1()

	}()

	p := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sess.NonceTPM(),
		PolicySession: sess.Handle(),
	}

	up, err := util.CPBytes(p)
	if err != nil {
		log.Fatalf("error creating PolicySecret Bytes: %v", err)
	}
	log.Printf("PolicySecret Bytes: %s\n", hex.EncodeToString(up))
	_, err = p.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicySecret: %v", err)
	}

	// verify the digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	aesTemplate := tpm2.TPMTPublic{
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
		AuthPolicy: pgd.PolicyDigest,
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

	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(aesTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM  %v", err)
	}

	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	data := []byte("foooo")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalf("can't read rsa details %v", err)
	}

	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	// _, err = tpm2.PolicySecret{
	// 	AuthHandle:    tpm2.TPMRHEndorsement,
	// 	PolicySession: sess2.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("executing PolicySecret: %v", err)
	// }

	tp2 := &tpm2.PolicySecret{
		PolicySession: sess2.Handle(),
	}

	ps, err := util.ReqParametersPolicySecret(up, tp2)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}

	_, err = ps.Execute(rwr)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}

	keyAuth2 := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   sess2,
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth2, iv, data, false)

	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	log.Printf("IV: %s", hex.EncodeToString(iv))
	log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

	sess3, cleanup3, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup3()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: sess3.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing PolicySecret: %v", err)
	}

	keyAuth3 := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   sess3,
	}

	decrypted, err := encryptDecryptSymmetric(rwr, keyAuth3, iv, encrypted, true)
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}

	log.Printf("Decrypted %s", string(decrypted))

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
