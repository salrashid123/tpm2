package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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

var (
	secret       = flag.String("secret", "meet me at...", "secret")
	ekPubFilepub = flag.String("ekPubFile", "ek.bin", "ekPub file")
	tpmPath      = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	pcr          = flag.Int("pcr", 23, "PCR to seal data to. Must be within [0, 23].")
	pcrValue     = flag.String("pcrValue", "0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea", "PCR value. on GCP Shielded VM, debian10 with secureboot: 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea is for PCR 0")
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

	log.Printf("======= createPrimary ========")

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	log.Printf("======= create ========")

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
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
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
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

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(23),
			},
		},
	}

	q, err := tpm2.Quote{
		SignHandle: rsaKeyResponse.ObjectHandle,
		QualifyingData: tpm2.TPM2BData{
			Buffer: []byte(*secret),
		},
		PCRSelect: sel,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	pub, err := rsaKeyResponse.OutPublic.Contents()
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

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	att, err := q.Quoted.Contents()
	if err != nil {
		log.Fatalf("Failed to getting attestation: %v", err)
	}
	log.Printf("attestation secret:   [%s]", string(att.ExtraData.Buffer))

	rsassa, err := q.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

	digest := sha256.Sum256([]byte(q.Quoted.Bytes()))

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	log.Printf("verified")
}
