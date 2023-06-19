package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

var (
	grpcport = flag.String("grpcport", "", "grpcport")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
)

const (
	tpmDevice             = "/dev/tpm0"
	encryptionCertNVIndex = 0x01c00002
)

func main() {

	flag.Parse()

	// on client create SKR cert
	rwc, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer rwc.Close()

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

	rwc.Close()

	// ********** first do remote attestation so that the AK i trusted on the 'server'
	// 1. on client
	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	eks, err := tpm.EKs()
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	ek := eks[0]
	//log.Printf("ek %v", ek.Certificate)

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	attestParams := ak.AttestationParameters()

	akBytes, err := ak.Marshal()
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	if err := os.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {
		log.Printf("Error %v", err)
		return
	}

	attestParametersBytes := new(bytes.Buffer)
	err = json.NewEncoder(attestParametersBytes).Encode(attestParams)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	// send TPM version, EK, and attestParametersBytes to the server

	// 2. on server

	serverAttestationParameter := &attest.AttestationParameters{}
	err = json.NewDecoder(attestParametersBytes).Decode(serverAttestationParameter)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ek.Public,
		AK:         *serverAttestationParameter,
	}
	akp, err := attest.ParseAKPublic(attest.TPMVersion20, attestParams.Public)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	skBytes, err := x509.MarshalPKIXPublicKey(akp.Public)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: skBytes,
		},
	)

	log.Printf("ak public \n%s\n", akPubPEM)

	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	log.Printf("Outbound Secret: %s\n", base64.StdEncoding.EncodeToString(secret))

	// return encrypted credentials to client

	// 3. on client
	akBytes, err = os.ReadFile("encrypted_aik.json")
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	ak, err = tpm.LoadAK(akBytes)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	secret, err = ak.ActivateCredential(tpm, *encryptedCredentials)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	log.Printf("Inbound Secret %s\n", base64.StdEncoding.EncodeToString(secret))

	// return inbound secret to server

	// 4. server compares the outbound and inbound secrets
	// done with attestation, now use ak to do quote verify

	// **** end remote attestation

	// *** start quote_verify
	// 5. on server
	// send to client a list of pcrs and plaintext nonce="foo" to create the code against
	nonce := []byte("foo")

	// on client

	platformAttestation, err := tpm.AttestPlatform(ak, nonce, nil)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	platformAttestationBytes := new(bytes.Buffer)
	err = json.NewEncoder(platformAttestationBytes).Encode(platformAttestation)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	// send TPM version, EK, and platformAttestationBytes to the server

	// on server

	serverPlatformAttestationParameter := &attest.PlatformParameters{}
	err = json.NewDecoder(platformAttestationBytes).Decode(serverPlatformAttestationParameter)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	// on server, use original attestParams.Public to verify quote

	pub, err := attest.ParseAKPublic(tpm.Version(), attestParams.Public)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	// compare the public key used during quote against the attested public key;

	qakBytes, err := x509.MarshalPKIXPublicKey(pub.Public)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}
	qakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: qakBytes,
		},
	)

	log.Printf("quote-attested public \n%s\n", qakPubPEM)

	if base64.StdEncoding.EncodeToString(qakPubPEM) != base64.StdEncoding.EncodeToString(akPubPEM) {
		log.Printf("Attested key does not match value in quote")
		os.Exit(1)
	}

	for _, quote := range serverPlatformAttestationParameter.Quotes {
		if err := pub.Verify(quote, serverPlatformAttestationParameter.PCRs, nonce); err != nil {
			log.Printf("Error %v", err)
			return
		}
	}

	el, err := attest.ParseEventLog(serverPlatformAttestationParameter.EventLog)
	if err != nil {
		log.Printf("Error %v", err)
		return
	}

	if _, err := el.Verify(serverPlatformAttestationParameter.PCRs); err != nil {
		log.Printf("Error %v", err)
		return
	}

}
