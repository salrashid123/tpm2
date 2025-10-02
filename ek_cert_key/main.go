package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// TPM2_EK_NV_INDEX=0x1c10000

const (
	tpmDevice     = "/dev/tpm0"
	emptyPassword = ""
)

const (
	// RSA 2048 EK Cert.
	EKCertNVIndexRSA uint32 = 0x01c00002
	// ECC P256 EK Cert.
	EKCertNVIndexECC uint32 = 0x01c0000a

	EKReservedHandle uint32 = 0x81010001

// 2.2.1.4 Low Range
// The Low Range is at NV Indices 0x01c00002 - 0x01c0000c.
// 0x01c00002 RSA 2048 EK Certificate
// 0x01c00003 RSA 2048 EK Nonce
// 0x01c00004 RSA 2048 EK Template
// 0x01c0000a ECC NIST P256 EK Certificate
// 0x01c0000b ECC NIST P256 EK Nonce
// 0x01c0000c ECC NIST P256 EK Template
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	nv      = flag.Uint("nv", 0x1500000, "nv to use") //tpm2_nvundefine 0x1500000
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

	log.Printf("======= Read NV for EK ========")

	akTemplatebytes, err := nvReadEX(rwr, tpmutil.Handle(EKCertNVIndexRSA))
	if err != nil {
		log.Fatalf("ERROR:  could not read nv index : %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: akTemplatebytes,
	}

	var pemBuffer bytes.Buffer
	err = pem.Encode(&pemBuffer, pemBlock)
	if err != nil {
		fmt.Println("Error encoding PEM:", err)
		return
	}
	pemBytes := pemBuffer.Bytes()
	fmt.Println(string(pemBytes))

	log.Printf("======= EK ========")

	// read from handle
	// EKReservedHandle uint32 = 0x81010001
	cCreateEK, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(EKReservedHandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}
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

	log.Printf("RSA  public \n%s\n", string(primaryEKPEMByte))

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
