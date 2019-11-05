package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"io/ioutil"
)

var (
	pemFile = flag.String("pemFile", "", "Path to input PEM File")
	tssKey  = flag.String("tssKey", "", "Path to output tssKey File")
)

const (
	hexHeader = "013a0001000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa00060080004300100800000000000100"
)

func main() {
	flag.Parse()

	if *pemFile == "" {
		fmt.Fprintf(os.Stderr, "Must provide value for pemFile")
		os.Exit(1)
	}
	if *tssKey == "" {
		fmt.Fprintf(os.Stderr, "Must provide value for pemFile")
		os.Exit(1)
	}

	dat, err := ioutil.ReadFile(*pemFile)
	if err != nil {
		log.Fatalf("Failed to read PEM File: %v", err)
	}
	block, _ := pem.Decode([]byte(dat))
	if block == nil {
		log.Fatalf("failed to parse certificate PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to ParsePKIXPublicKey")
	}
	//ekPubPEM := pem.EncodeToMemory(block)

	pk := pub.(*rsa.PublicKey)
	log.Printf("Public Key modulus %v", fmt.Sprintf("%x", pk.N))

	dec, err := hex.DecodeString(hexHeader + fmt.Sprintf("%x", pk.N))
	if block == nil {
		log.Fatalf("failed to Decode modulus to hex")
	}

	err = ioutil.WriteFile(*tssKey, dec, 0644)
	if err != nil {
		log.Fatal(err)
	}

	return
}
