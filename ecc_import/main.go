package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
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
	tpmPath    = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	pemFile    = flag.String("pemFile", "private.pem", "Private key PEM format file")
	dataToSign = flag.String("datatosign", "foo", "data to sign")
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

	log.Println("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	kdata, err := os.ReadFile(*pemFile)

	if err != nil {
		log.Fatalf("     Unable to read key %v", err)
	}
	block, _ := pem.Decode(kdata)
	if block == nil {
		log.Fatalf("     Failed to decode PEM block containing the key %v", err)
	}
	pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("     Failed to parse PEM block containing the key %v", err)
	}

	k := pvp.(*ecdsa.PrivateKey)

	pk := k.PublicKey

	log.Printf("======= createPrimary ======== ")

	data := []byte(*dataToSign)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", hex.EncodeToString(primaryKey.Name.Buffer))

	// ecc

	eccTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))), //pk.X.Bytes(), // pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))), //pk.Y.Bytes(), // pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))),
				},
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgECC,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgECC,
			&tpm2.TPM2BECCParameter{Buffer: k.D.FillBytes(make([]byte, len(k.D.Bytes())))},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(eccTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create ec %v", err)
	}

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(eccTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create ecc %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("======= generate test signature with ECC key ========")
	digest := sha256.Sum256(data)

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	eccSign, err := sign.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	ecs, err := eccSign.Signature.Signature.ECDSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature: R %s\n", base64.StdEncoding.EncodeToString(ecs.SignatureR.Buffer))
	log.Printf("signature: S %s\n", base64.StdEncoding.EncodeToString(ecs.SignatureS.Buffer))

	eccKeyResponse := tpm2.New2B(eccTemplate)

	outPub, err := eccKeyResponse.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	ecDetail, err := outPub.Parameters.ECCDetail()
	if err != nil {
		log.Fatalf(": error reading ec details %v", err)
	}
	crv, err := ecDetail.CurveID.Curve()
	if err != nil {
		log.Fatalf(": error reading ecc curve %v", err)
	}
	eccUnique, err := outPub.Unique.ECC()
	if err != nil {
		log.Fatalf(": error reading ecc unique %v", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	x := big.NewInt(0).SetBytes(ecs.SignatureR.Buffer)
	y := big.NewInt(0).SetBytes(ecs.SignatureS.Buffer)

	ok := ecdsa.Verify(pubKey, digest[:], x, y)
	if !ok {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	log.Println("Verified")
}
