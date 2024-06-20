package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath    = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
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

	log.Printf("======= createPrimary ========")

	data := []byte(*dataToSign)

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}
	primaryKey, err := cmdPrimary.Execute(rwr)
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
	log.Printf("primaryKey handle Value %d\n", cmdPrimary.PrimaryHandle.HandleValue())

	// ecc

	eccTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
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
	}

	eccKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create ecc %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: eccKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
	// *************** evict

	// https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-3.1.8
	// _, err = tpm2.EvictControl{
	// 	Auth: tpm2.TPMRHOwner,
	// 	ObjectHandle: &tpm2.NamedHandle{
	// 		Handle: primaryKey.ObjectHandle,
	// 		Name:   primaryKey.Name,
	// 	},
	// 	PersistentHandle: tpm2.TPMHandle(*persistenthandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create rsa %v", err)
	// }

	/// ============================ =================================================================================================

	log.Printf("======= generate test signature with RSA key ========")
	digest := sha256.Sum256(data)

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: eccKeyResponse.ObjectHandle,
			Name:   eccKeyResponse.Name,
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

	rspSign, err := sign.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	outPub, err := eccKeyResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}

	ecDetail, err := outPub.Parameters.ECCDetail()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	crv, err := ecDetail.CurveID.Curve()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}

	eccUnique, err := outPub.Unique.ECC()
	if err != nil {
		log.Fatalf("Failed to get ecc public key: %v", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	ecsig, err := rspSign.Signature.Signature.ECDSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}

	out := append(ecsig.SignatureR.Buffer, ecsig.SignatureS.Buffer...)
	log.Printf("raw signature: %v\n", base64.StdEncoding.EncodeToString(out))
	log.Printf("ecpub: x %v\n", pubKey)
	ok := ecdsa.Verify(pubKey, digest[:], big.NewInt(0).SetBytes(ecsig.SignatureR.Buffer), big.NewInt(0).SetBytes(ecsig.SignatureS.Buffer))
	if !ok {
		log.Fatalf("Failed to verify signature: %v", err)
	}

}
