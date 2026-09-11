package main

import (
	"bytes"
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
	"math/big"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath                = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	newKeyFile             = flag.String("newKeyFile", "output/nk.pem", "file to write the newkey")
	newKeyPubPEM           = flag.String("newKeyPubPEM", "output/nkpub.pem", "file to write the newkey")
	akKeyFile              = flag.String("akKeyFile", "output/ak.pem", "file to write the ekpub")
	akPubFile              = flag.String("akPubFile", "output/akpub.pem", "file to write the akpub")
	certifyInfoFile        = flag.String("certifyInfoFile", "output/certify.bin", "file to write the newkey")
	secret                 = flag.String("secret", "meet me at...", "secret")
	certificationSignature = flag.String("certificationSignature", "output/certifysignature.bin", "file to write the newkey")
	eccTemplate            = tpm2.TPMTPublic{
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

	log.Println("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= EKPub ========")

	primarH2Key, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primarH2Key.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", hex.EncodeToString(primarH2Key.Name.Buffer))

	nkKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.NamedHandle{
			Handle: primarH2Key.ObjectHandle,
			Name:   primarH2Key.Name,
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: nkKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primarH2Key.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	outPub, err := nkKeyResponse.OutPublic.Contents()
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
	b4, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}
	log.Printf("NewKey Name %s\n", hex.EncodeToString(nkKeyResponse.Name.Buffer))
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b4,
	}
	keyPEMByte := pem.EncodeToMemory(block)
	log.Printf("ECC NewKey Key \n%s\n", string(keyPEMByte))

	err = os.WriteFile(*newKeyPubPEM, keyPEMByte, 0644)
	if err != nil {
		log.Fatal(err)
	}
	kf := keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Pubkey:    nkKeyResponse.OutPublic,
		Privkey:   nkKeyResponse.OutPrivate,
	}

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, &kf)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create key bytes: %v", err)
	}

	err = os.WriteFile(*newKeyFile, keyFileBytes.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

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

	c, err := os.ReadFile(*akKeyFile)
	if err != nil {
		log.Fatalf("can't load keys %q: %v", *tpmPath, err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("can't decode keys %q: %v", *tpmPath, err)
	}

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sess.NonceTPM(),
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicySecret: %v", err)
	}

	akKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   sess,
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		log.Fatalf("can't load  hmacKey : %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: akKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// certify the new key
	certifyResponse, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: nkKeyResponse.ObjectHandle,
			Name:   nkKeyResponse.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: akKey.ObjectHandle,
			Name:   akKey.Name,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: []byte(*secret),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't get Certify %v", err)
	}

	ceritfySignature, err := certifyResponse.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("can't certifyResponse signature %v", err)
	}
	log.Printf("Certify Response of Signature \n%v\n", base64.StdEncoding.EncodeToString(ceritfySignature.Sig.Buffer))

	certifyAttest, err := certifyResponse.CertifyInfo.Contents()
	if err != nil {
		log.Fatalf("can't certifyResponse contents %v", err)
	}

	certifyInfo, err := certifyAttest.Attested.Certify()
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	log.Printf("Certify Response for Key Name %s\n", hex.EncodeToString(certifyInfo.Name.Buffer))
	log.Printf("Certify Extra Data %s\n", string(certifyAttest.ExtraData.Buffer))

	b := tpm2.Marshal(certifyResponse.CertifyInfo)
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	csbytes := tpm2.Marshal(certifyResponse.Signature)

	err = os.WriteFile(*certificationSignature, csbytes, 0644)
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	err = os.WriteFile(*certifyInfoFile, b, 0644)
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	hsh := crypto.SHA256.New()
	hsh.Write(certifyResponse.CertifyInfo.Bytes())

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

	if err := rsa.VerifyPKCS1v15(rsaPubA, crypto.SHA256, hsh.Sum(nil), ceritfySignature.Sig.Buffer); err != nil {
		log.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
	log.Printf("Attestation Verified")

}
