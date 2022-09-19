package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

const (
	tpmDevice             = "/dev/tpm0"
	signCertNVIndex       = 0x01c10000
	signKeyNVIndex        = 0x01c10001
	encryptionCertNVIndex = 0x01c00002
	emptyPassword         = ""
)

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {

	flag.Parse()
	log.Println("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			log.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				log.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			log.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	log.Printf("%d handles flushed\n", totalHandles)

	// *****************

	log.Printf("     Load SigningKey and Certifcate ")
	kk, err := client.EndorsementKeyFromNvIndex(rwc, signKeyNVIndex)
	if err != nil {
		log.Printf("ERROR:  could not get EndorsementKeyFromNvIndex: %v", err)
		return
	}
	pubKey := kk.PublicKey().(*rsa.PublicKey)
	akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Printf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		return
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	log.Printf("     Signing PEM \n%s", string(akPubPEM))

	// begin sign with AK using go-tpm-tools
	aKdataToSign := []byte("foobar")
	r, err := kk.SignData(aKdataToSign)
	if err != nil {
		log.Printf("ERROR:  error singing with go-tpm-tools: %v", err)
		return
	}

	log.Printf("     AK Signed Data using go-tpm-tools %s", base64.StdEncoding.EncodeToString(r))

	// begin sign using go-tpm
	aKkeyHandle := kk.Handle()
	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Printf("ERROR:  could  StartAuthSession (signing): %v", err)
		return
	}
	if _, _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		log.Printf("ERROR:  could  PolicySecret (signing): %v", err)
		return
	}

	aKdigest, aKvalidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, aKdataToSign, tpm2.HandleOwner)
	if err != nil {
		log.Printf("ERROR:  could  StartAuthSession (signing): %v", err)
		return
	}
	log.Printf("     AK Issued Hash %s", base64.StdEncoding.EncodeToString(aKdigest))
	aKsig, err := tpm2.Sign(rwc, aKkeyHandle, emptyPassword, aKdigest, aKvalidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		log.Printf("ERROR:  could  Sign (signing): %v", err)
		return
	}
	log.Printf("     AK Signed Data %s", base64.StdEncoding.EncodeToString(aKsig.RSA.Signature))

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, aKdigest, aKsig.RSA.Signature); err != nil {
		log.Printf("ERROR:  could  VerifyPKCS1v15 (signing): %v", err)
		return
	}
	log.Printf("     Signature Verified")
	err = tpm2.FlushContext(rwc, sessCreateHandle)
	if err != nil {
		log.Printf("ERROR:  could  flush SessionHandle: %v", err)
		return
	}
	err = tpm2.FlushContext(rwc, aKkeyHandle)
	if err != nil {
		log.Printf("ERROR:  could  flush aKkeyHandle: %v", err)
		return
	}
	kk.Close()

}
