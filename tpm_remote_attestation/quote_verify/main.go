package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	secret              = flag.String("secret", "meet me at...", "secret")
	ekPubFile           = flag.String("ekPubFile", "output/ekpub.pem", "file to write the ekpub")
	akPubFile           = flag.String("akPubFile", "output/akpub.pem", "file to write the akpub")
	quotedFile          = flag.String("quotedFile", "output/quoted.bin", "file to write the quoteResponse")
	quotedSignatureFile = flag.String("quotedSignatureFile", "output/quotedsignature.bin", "file to write the quoteSignature")
	pcr                 = flag.Int("pcr", 23, "PCR to seal data to. Must be within [0, 23].")

	RSAAKTemplate = tpm2.TPMTPublic{
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
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	ep, err := os.ReadFile(*ekPubFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	block, _ := pem.Decode(ep)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return
	}
	rsaPub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error converting encryptingPublicKey to rsa")
		return
	}

	ekPububFromPEMTemplate := tpm2.RSAEKTemplate

	ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPub.N.Bytes(),
		},
	)

	ap, err := os.ReadFile(*akPubFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	blockA, _ := pem.Decode(ap)
	parsedKeyA, err := x509.ParsePKIXPublicKey(blockA.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing ak public key : %v", err)
		return
	}
	rsaPubA, ok := parsedKeyA.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error converting ak to rsa")
		return
	}

	RSAAKTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPubA.N.Bytes(),
		},
	)
	sim, err := simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}
	defer sim.Close()
	rwrs := transport.FromReadWriter(sim)
	loadedEk, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
	}.Execute(rwrs)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}
	log.Printf("key Primary Name: %v\n", hex.EncodeToString(loadedEk.Name.Buffer))

	loadedAK, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.New2B(RSAAKTemplate),
	}.Execute(rwrs)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}

	log.Printf("key Name: %v\n", hex.EncodeToString(loadedAK.Name.Buffer))

	ec, err := os.ReadFile(*quotedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	qs, err := os.ReadFile(*quotedSignatureFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	q2, err := tpm2.Unmarshal[tpm2.TPMSAttest, *tpm2.TPMSAttest](ec)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("attestation secret:   [%s]", string(q2.ExtraData.Buffer))

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](qs)
	if err != nil {
		log.Fatal(err)
	}

	rsassa, err := sig.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

	digest := sha256.Sum256(ec)

	if err := rsa.VerifyPKCS1v15(rsaPubA, crypto.SHA256, digest[:], rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	log.Printf("verified")
}
