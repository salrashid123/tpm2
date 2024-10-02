package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
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
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
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

	log.Printf("======= EK ========")

	cCreateEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateEK.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	// read from handle
	// cCreateGCEEK, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(EKReservedHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	// }
	log.Printf("Name %s\n", hex.EncodeToString(cCreateEK.Name.Buffer))

	rsaEKpub, err := cCreateEK.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rsaEKDetail, err := rsaEKpub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rsaEKUnique, err := rsaEKpub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	primaryRsaEKPub, err := tpm2.RSAPub(rsaEKDetail, rsaEKUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	b4, err := x509.MarshalPKIXPublicKey(primaryRsaEKPub)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b4,
	}
	primaryEKPEMByte := pem.EncodeToMemory(block)

	log.Printf("RSA createPrimary public \n%s\n", string(primaryEKPEMByte))

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

	// https://github.com/google/go-attestation/blob/f203ad309099f8efdef5f222d974fb8a2a8c1cd1/attest/tpm.go#L51
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
			Handle: cCreateEK.ObjectHandle,
			Name:   cCreateEK.Name,
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
	log.Printf("RSA Attestation Key \n%s\n", string(keyPEMByte))
	log.Printf("RSA Attestation Name %s\n", hex.EncodeToString(rsaKeyResponse.Name.Buffer))

	sessK1, cleanup1K1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		cleanup1K1()
	}()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sessK1.NonceTPM(),
		PolicySession: sessK1.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicySecret: %v", err)
	}

	rtK1 := tpm2.TPMTPublic{
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
	rsaKeyResponseK1, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: cCreateEK.ObjectHandle,
			Name:   cCreateEK.Name,
			Auth:   sessK1,
		},
		InPublic: tpm2.New2BTemplate(&rtK1),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponseK1.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rpubK1, err := rsaKeyResponseK1.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rrsaDetailK1, err := rpubK1.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rrsaUniqueK1, err := rpubK1.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	rrsaPubK1, err := tpm2.RSAPub(rrsaDetailK1, rrsaUniqueK1)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	blockK1 := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rrsaPubK1.N.Bytes(),
	}
	keyPEMByteK1 := pem.EncodeToMemory(blockK1)
	log.Printf("RSA K1 \n%s\n", string(keyPEMByteK1))
	log.Printf("RSA K1 Name %s\n", hex.EncodeToString(rsaKeyResponseK1.Name.Buffer))
	log.Printf("Begin Certification of K1 \n")

	certifyResponse, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: rsaKeyResponseK1.ObjectHandle,
			Name:   rsaKeyResponseK1.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: []byte("foooo"),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't get Certify %v", err)
	}

	crs, err := certifyResponse.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("can't certifyResponse signature %v", err)
	}
	log.Printf("Certify Response of Signature \n%v\n", base64.StdEncoding.EncodeToString(crs.Sig.Buffer))

	cr, err := certifyResponse.CertifyInfo.Contents()
	if err != nil {
		log.Fatalf("can't certifyResponse contents %v", err)
	}

	c, err := cr.Attested.Certify()
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}

	log.Printf("Certify Response for Key Name %s\n", hex.EncodeToString(c.Name.Buffer))
	log.Printf("Certify Extra Data %s\n", string(cr.ExtraData.Buffer))

	hsh := crypto.SHA256.New()
	hsh.Write(certifyResponse.CertifyInfo.Bytes())

	if err := rsa.VerifyPKCS1v15(rrsaPub, crypto.SHA256, hsh.Sum(nil), crs.Sig.Buffer); err != nil {
		log.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
	log.Printf("Attestation Verified")

}
