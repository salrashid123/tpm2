package main

/*
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPMB="127.0.0.1:2321"


 go run main.go --parentKeyType=ecc_srk  --tpm-path=127.0.0.1:2321

*/

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"slices"

	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpmcopy"
)

const ()

// go run main.go --parentKeyType=ecc_srk  --tpm-path=127.0.0.1:2321

var (
	parentKeyType = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2|rsa_srk|ecc_srk (default rsa_ek)")

	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Create: Path to the TPM device (character device or a Unix socket).")
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
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
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

	var t tpm2.TPMTPublic
	var primaryHandle tpm2.TPMHandle

	switch *parentKeyType {
	case tpmcopy.RSA_EK:
		t = tpm2.RSAEKTemplate
		primaryHandle = tpm2.TPMRHEndorsement
	case tpmcopy.ECC_EK:
		t = tpm2.ECCEKTemplate
		primaryHandle = tpm2.TPMRHEndorsement
	case tpmcopy.H2:
		t = keyfile.ECCSRK_H2_Template
		primaryHandle = tpm2.TPMRHOwner
	case tpmcopy.RSA_SRK:
		t = tpm2.RSASRKTemplate
		primaryHandle = tpm2.TPMRHOwner
	case tpmcopy.ECC_SRK:
		t = tpm2.ECCSRKTemplate
		primaryHandle = tpm2.TPMRHOwner
	default:
		fmt.Fprintf(os.Stderr, "unsupported --parentKeyType must be either rsa or ecc, got %v\n", *parentKeyType)
		return 1
	}

	cCreateEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Name:   tpm2.HandleName(primaryHandle),
			Auth:   tpm2.PasswordAuth([]byte(nil)),
		},
		InPublic: tpm2.New2B(t),
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't create object TPM: %v", err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateEK.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %v", err)
		}
	}()
	b, err := getPublicKey(rwc, cCreateEK.ObjectHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't getting public key %v", err)
		return 1
	}
	fmt.Printf("%s\n", b)
	return 0

}

func getPublicKey(dev io.ReadWriter, handle tpm2.TPMHandle) ([]byte, error) {

	if handle == 0 {
		return nil, fmt.Errorf("TPM Handle must get set")
	}

	rwr := transport.FromReadWriter(dev)

	ppub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(handle),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error reading  handle public %v", err)
	}

	pub, err := ppub.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("can't read public object  %v", err)
	}

	// check if the key is either rsa or ecc

	var b []byte

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("can't read RSA details %v", err)
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("can't read RSA public unique: %v", err)
		}

		pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, fmt.Errorf("can't read RSA rsapub unique: %v", err)
		}

		b, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to convert RSA  PublicKey: %v", err)
		}
	case tpm2.TPMAlgECC:
		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("failed to get ecc public: %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf("failed to get ecc public: %v", err)
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("failed to get ecc public key: %v", err)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		b, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to convert ECC PublicKey: %v", err)
		}
	default:
		fmt.Fprintf(os.Stdout, "unsupported public key type %v", pub)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	return akPubPEM, nil
}
