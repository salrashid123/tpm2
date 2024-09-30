package main

import (
	"crypto/x509"
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

// 2.3.1 Key Handle Assignments
// https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf

// https://github.com/google/go-tpm/blob/364d5f2f78b95ba23e321373466a4d881181b85d/legacy/tpm2/tpm2.go#L1429

// github.com/google/go-tpm-tools@v0.4.4/client/handles.go
// [go-tpm-tools/client](https://pkg.go.dev/github.com/google/go-tpm-tools/client#pkg-constants)

// pg 28 https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
const (
	// RSA 2048 AK.
	GceAKCertNVIndexRSA     uint32 = 0x01c10000
	GceAKTemplateNVIndexRSA uint32 = 0x01c10001
	// ECC P256 AK.
	GceAKCertNVIndexECC     uint32 = 0x01c10002
	GceAKTemplateNVIndexECC uint32 = 0x01c10003

	// RSA 2048 EK Cert.
	EKCertNVIndexRSA uint32 = 0x01c00002
	// ECC P256 EK Cert.
	EKCertNVIndexECC uint32 = 0x01c0000a

	EKReservedHandle uint32 = 0x81010001
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
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

	log.Printf("======= Read NV for GCE ak ========")

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

	// extract out the actual rsa public pem key details

	gceAKpub, err := cCreateGCEAK.OutPublic.Contents()
	if err != nil {
		log.Fatalf("can't read public object %q: %v", *tpmPath, err)
	}
	rsaGCEAKDetail, err := gceAKpub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("can't read rsa details %q: %v", *tpmPath, err)
	}
	rsaGCEAKUnique, err := gceAKpub.Unique.RSA()
	if err != nil {
		log.Fatalf("can't read public unique %q: %v", *tpmPath, err)
	}

	rsaGCEAKPub, err := tpm2.RSAPub(rsaGCEAKDetail, rsaGCEAKUnique)
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

	log.Printf("======= createPrimary RSAEKTemplate ========")

	// read from template
	cCreateGCEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateGCEEK.ObjectHandle,
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
	log.Printf("Name %s\n", hex.EncodeToString(cCreateGCEEK.Name.Buffer))

	rsaEKpub, err := cCreateGCEEK.OutPublic.Contents()
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
	log.Printf("GCE EKPublic: \n%s\n", string(primaryEKPEMByte))

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
