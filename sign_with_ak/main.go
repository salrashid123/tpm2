package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	secret  = flag.String("secret", "meet me at...", "secret")
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

	log.Printf("======= createPrimary RSAEKTemplate ========")

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
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

	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	primaryRsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: primaryRsaPub.N.Bytes(),
	}
	primaryPEMByte := pem.EncodeToMemory(block)
	log.Printf("RSA Primary \n%s\n", string(primaryPEMByte))

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		cleanup1()

	}()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sess.NonceTPM(),
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicySecret: %v", err)
	}

	rt := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	}
	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   sess,
		},
		InPublic: tpm2.New2BTemplate(&rt),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rpub, err := rsaKeyResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rrsaDetail, err := rpub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rrsaUnique, err := rpub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	rrsaPub, err := tpm2.RSAPub(rrsaDetail, rrsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rrsaPub.N.Bytes(),
	}
	keyPEMByte := pem.EncodeToMemory(block)
	log.Printf("RSA Key \n%s\n", string(keyPEMByte))

	// *****************************************************

	log.Printf("======= generate test signature with RSA key ========")
	data := []byte("foo")

	h, err := tpm2.Hash{
		Hierarchy: tpm2.TPMRHEndorsement,
		HashAlg:   tpm2.TPMAlgSHA256,
		Data: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: h.OutHash.Buffer,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHEndorsement,
			Digest: tpm2.TPM2BDigest{
				Buffer: h.Validation.Digest.Buffer,
			},
		},
	}

	rspSign, err := sign.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

	akhsh := crypto.SHA256.New()
	akhsh.Write(data)
	if err := rsa.VerifyPKCS1v15(rrsaPub, crypto.SHA256, akhsh.Sum(nil), rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
}
