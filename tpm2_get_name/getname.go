package main

import (
	//"context"

	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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

var (
	tpmPath   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	ekpubFile = flag.String("ekpubFile", "output.dat", "Path to the ekPublicKey.")
)

/*
recreates the "name" from an ek rsa key

$ go run main.go
Name 000b7d5ae2283593ce63281bd4a5b681b50ceff54a49e17ee6e40bc8e82f47967d55
PEM
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnMDg8UTDAfb8+wdYQFbz
M3XkvBDBY30G77JlIuYH4FElqNUFruIrdGCW21jqCwauFJC/He+fjYJE7giy7TGi
fr6yLn+f7fIeVYKB5bZofaO/8uRdRD4GsG8+Y3ywQdEsQuZ23bmAZHBZjfHdWGi8
DYWTjIWfSaSRkKKLovaaV0vdLR+3AbVcswiTFYtxMjkHn/ss4CkBPGIzqyqFchFV
I/DAhXn/xTtKPZYxLNelbvLH1hYoHEIyHfvw5nf+2CxINdVBWx5S2V6nFuzLXPYC
WGtoAkVO7oM+So41pIy/C8iOix6NtfiNyOy7LfXzkvajiEX/Gn6c6wXiHNhayFLv
2QIDAQAB
-----END PUBLIC KEY-----

Name 000b7d5ae2283593ce63281bd4a5b681b50ceff54a49e17ee6e40bc8e82f47967d55
*/
const ()

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
	//ctx := context.Background()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %q: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error reading rsa public %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	fmt.Printf("Name %s\n", hex.EncodeToString(createEKRsp.Name.Buffer))

	// to write the public to bytes and back
	// bt := createEKRsp.OutPublic.Bytes()
	// cc := tpm2.BytesAs2B[tpm2.TPMTPublic](bt)

	// print the rsa key and recreate the "name" using key details

	c, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		log.Fatalf("error reading rsa public %v", err)
	}

	rsaDetail, err := c.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("error reading rsa public %v", err)
	}
	rsaUnique, err := c.Unique.RSA()
	if err != nil {
		log.Fatalf("error reading rsa unique %v", err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	b, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	fmt.Printf("PEM \n%s\n", string(publicKeyPEM))

	// recreate the "name" using just the RSA Public Key modulus
	// https://github.com/google/go-tpm-tools/blob/6a70865538a8e7e85b95164bba3ae855f4bc4f68/server/key_conversion.go#L30

	u := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPub.N.Bytes(),
		},
	)

	ekPububFromPEMTemplate := tpm2.RSAEKTemplate

	ekPububFromPEMTemplate.Unique = u

	n, err := tpm2.ObjectName(&ekPububFromPEMTemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	fmt.Printf("Name %s\n", hex.EncodeToString(n.Buffer))

}
