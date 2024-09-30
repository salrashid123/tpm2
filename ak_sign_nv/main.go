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

const (
	GceAKTemplateNVIndexRSA uint32 = 0x01c10001
)

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

	log.Printf("======= createPrimary RSAEKTemplate ========")

	// read from template
	// cCreateGCEEK, err := tpm2.CreatePrimary{
	// 	PrimaryHandle: tpm2.TPMRHEndorsement,
	// 	InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	// }

	akTemplatebytes, err := nvReadEX(rwr, tpmutil.Handle(GceAKTemplateNVIndexRSA))
	if err != nil {
		log.Fatalf("ERROR:  could not read nv index for GceAKTemplateNVIndexRSA: %v", err)
	}

	tb := tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](akTemplatebytes)

	cCreateGCEAK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tb,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateGCEAK.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	log.Printf("Name %s\n", hex.EncodeToString(cCreateGCEAK.Name.Buffer))

	pub, err := cCreateGCEAK.OutPublic.Contents()
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

	rsaGCEAKPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("can't read rsapub unique %q: %v", *tpmPath, err)
	}

	b2, err := x509.MarshalPKIXPublicKey(rsaGCEAKPub)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	akGCEPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b2,
		},
	)
	log.Printf("GCE AKPublic: \n%v", string(akGCEPubPEM))

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

	// sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	// if err != nil {
	// 	log.Fatalf("setting up trial session: %v", err)
	// }
	// defer func() {
	// 	cleanup1()

	// }()

	// _, err = tpm2.PolicySecret{
	// 	AuthHandle:    tpm2.TPMRHEndorsement,
	// 	NonceTPM:      sess.NonceTPM(),
	// 	PolicySession: sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing PolicySecret: %v", err)
	// }

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: cCreateGCEAK.ObjectHandle,
			Name:   cCreateGCEAK.Name,
			Auth:   tpm2.PasswordAuth(nil),
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
	if err := rsa.VerifyPKCS1v15(rsaGCEAKPub, crypto.SHA256, akhsh.Sum(nil), rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
}

func nvReadEX(rwr transport.TPM, index tpmutil.Handle) ([]byte, error) {

	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}
	log.Printf("Name: %x", readPubRsp.NVName.Buffer)
	c, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	log.Printf("Size: %d", c.DataSize)

	getCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}
	getRsp, err := getCmd.Execute(rwr)
	if err != nil {
		return nil, err
	}

	tp, err := getRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}

	blockSize := int(tp.TPMProperty[0].Value)
	log.Printf("TPM Max NV buffer %d", blockSize)

	outBuff := make([]byte, 0, int(c.DataSize))
	for len(outBuff) < int(c.DataSize) {
		readSize := blockSize
		if readSize > (int(c.DataSize) - len(outBuff)) {
			readSize = int(c.DataSize) - len(outBuff)
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Name:   tpm2.HandleName(tpm2.TPMRHOwner),
				Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),
			Offset: uint16(len(outBuff)),
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		data := readRsp.Data.Buffer
		outBuff = append(outBuff, data...)
	}
	return outBuff, nil
}
