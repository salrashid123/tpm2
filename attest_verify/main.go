package main

import (
	"crypto"
	"flag"
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	//"github.com/google/go-attestation/attest"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {
	flag.Parse()

	var err error

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}
	defer ekk.Close()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer ak.Close()

	nonce := []byte("noncevalue")

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		log.Fatalf("failed to attest: %v", err)
	}

	//ims, err := server.VerifyAttestation(attestation, server.VerifyOpts{
	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	})
	if err != nil {
		log.Fatalf("failed to verify: %v", err)
	}
	log.Printf("Attestation Verified")
	//log.Printf("Machine State: %v", ims.RawEvents)

}
