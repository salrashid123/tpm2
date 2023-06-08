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
	// on client
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

	// on server

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

	// on client
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
	// server compares the outbound and inbound secrets
	// if theyr'e the same, the server will persist attestParametersBytes from earlier for use with stuff like quote/verify

	if err := os.WriteFile("aik.json", attestParametersBytes, 0600); err != nil {
		log.Printf("Error %v", err)
		return
	}

}
