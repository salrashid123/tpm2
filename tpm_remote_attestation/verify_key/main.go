package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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
	secret                 = flag.String("secret", "meet me at...", "secret")
	ekPubFile              = flag.String("ekPubFile", "output/ekpub.pem", "file to write the ekpub")
	akPubFile              = flag.String("akPubFile", "output/akpub.pem", "file to write the akpub")
	certifyInfoFile        = flag.String("certifyInfoFile", "output/certify.bin", "file to write the newkey")
	certificationSignature = flag.String("certificationSignature", "output/certifysignature.bin", "file to write the newkey")
	newKeyPubPEM           = flag.String("newKeyPubPEM", "output/nkpub.pem", "file to write the newkey")

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

	eccTemplate = tpm2.TPMTPublic{
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

	nkp, err := os.ReadFile(*newKeyPubPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	blocknk, _ := pem.Decode(nkp)
	parsedKeynk, err := x509.ParsePKIXPublicKey(blocknk.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return
	}
	nkEcPub, ok := parsedKeynk.(*ecdsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error converting encryptingPublicKey to rsa")
		return
	}

	eccTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{
				Buffer: nkEcPub.X.FillBytes(make([]byte, len(nkEcPub.X.Bytes()))), //pk.X.Bytes(), // pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))),
			},
			Y: tpm2.TPM2BECCParameter{
				Buffer: nkEcPub.Y.FillBytes(make([]byte, len(nkEcPub.Y.Bytes()))), //pk.Y.Bytes(), // pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))),
			},
		},
	)

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

	log.Printf("AK key Name: %v\n", hex.EncodeToString(loadedAK.Name.Buffer))

	epp, err := os.ReadFile(*ekPubFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	blockE, _ := pem.Decode(epp)
	parsedKeyE, err := x509.ParsePKIXPublicKey(blockE.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing ak public key : %v", err)
		return
	}
	rsaPubE, ok := parsedKeyE.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error converting ak to rsa")
		return
	}

	ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPubE.N.Bytes(),
		},
	)

	nkpname, err := tpm2.ObjectName(&eccTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing ak public key : %v", err)
		return
	}

	log.Printf("Derived Name %s\n", hex.EncodeToString(nkpname.Buffer))

	cfb, err := os.ReadFile(*certifyInfoFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	csb, err := os.ReadFile(*certificationSignature)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}
	cs, err := tpm2.Unmarshal[tpm2.TPMTSignature, *tpm2.TPMTSignature](csb)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	crs, err := cs.Signature.RSASSA()
	if err != nil {
		log.Fatalf("can't certifyResponse signature %v", err)
	}
	log.Printf("Certify Response of Signature \n%v\n", base64.StdEncoding.EncodeToString(crs.Sig.Buffer))

	ci, err := tpm2.Unmarshal[tpm2.TPM2BAttest, *tpm2.TPM2BAttest](cfb)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	ca, err := ci.Contents()
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	cri, err := ca.Attested.Certify()
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	log.Printf("Certify CreationObjectName %s\n", hex.EncodeToString(cri.Name.Buffer))

	log.Printf("Certify Extra Data %s\n", string(ca.ExtraData.Buffer))
	hsh := crypto.SHA256.New()
	hsh.Write(ci.Bytes())

	if err := rsa.VerifyPKCS1v15(rsaPubA, crypto.SHA256, hsh.Sum(nil), crs.Sig.Buffer); err != nil {
		log.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
	log.Printf("Attestation Verified")
}
