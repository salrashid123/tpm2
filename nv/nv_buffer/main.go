package main

import (
	"crypto/rand"
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

// TPM2_EK_NV_INDEX=0x1c10000
// tpm2_nvreadpublic | sed -n -e "/""$TPM2_EK_NV_INDEX""/,\$p" | sed -e '/^[ \r\n\t]*$/,$d' | grep "size" | sed 's/.*size.*://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]$//'
// 1516
// tpm2_nvread -s 1516  -C o $TPM2_EK_NV_INDEX |  openssl x509 --inform DER -text -noout  -in -

const (
	tpmDevice     = "/dev/tpm0"
	emptyPassword = ""
)

// https://github.com/google/go-tpm/blob/364d5f2f78b95ba23e321373466a4d881181b85d/legacy/tpm2/tpm2.go#L1429

// github.com/google/go-tpm-tools@v0.4.4/client/handles.go
// [go-tpm-tools/client](https://pkg.go.dev/github.com/google/go-tpm-tools/client#pkg-constants)

// GCE Attestation Key NV Indices
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
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
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
	log.Println("======= Init  ========")

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

	// get nv max buffer

	// tpm2_getcap properties-fixed | grep -A 1 TPM2_PT_NV_BUFFER_MAX
	// 	TPM2_PT_NV_BUFFER_MAX:
	// 	raw: 0x400   <<<<< 1024

	// $ tpm2_getcap properties-fixed | grep -A 1 TPM2_PT_NV_INDEX_MAX
	// TPM2_PT_NV_INDEX_MAX:
	//   raw: 0x800  <<<<< 2048

	getCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}
	getRsp, err := getCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("errpr Calling GetCapability: %v", err)
	}

	tp, err := getRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		log.Fatalf("error Calling TPMProperties: %v", err)
	}

	blockSize := int(tp.TPMProperty[0].Value)
	log.Printf("TPM Max NV buffer %d", blockSize)

	// *****************

	log.Printf("     Load SigningKey and Cert ")
	// read direct from nv template

	token := make([]byte, 2*blockSize) // can't be larger than TPM2_PT_NV_INDEX_MAX
	rand.Read(token)
	log.Println(base64.StdEncoding.EncodeToString(token))
	/// write

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte("p@ssw0rd"),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: tpm2.TPMHandle(*nv),
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
				},
				DataSize: uint16(2 * blockSize),
			}),
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		log.Fatalf("%v", err)
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		log.Fatalf("Calculating name of NV index: %v", err)
	}

	_, err = defs.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyPCR: %v", err)
	}

	batch := blockSize

	for i := 0; i < len(token); i += batch {
		j := i + batch
		if j > len(token) {
			j = len(token)
		}

		prewrite := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: pub.NVIndex,
				Name:   *nvName,
				Auth:   tpm2.PasswordAuth([]byte("p@ssw0rd")),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: pub.NVIndex,
				Name:   *nvName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: token[i:j],
			},
			Offset: uint16(i),
		}
		if _, err := prewrite.Execute(rwr); err != nil {
			log.Fatalf("Calling TPM2_NV_Write: %v", err)
		}

	}

	// read

	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(*nv),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	c, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		log.Fatalf("Calling TPM2_NV_ReadPublic Contents: %v", err)
	}
	log.Printf("Size: %d", c.DataSize)

	outBuff := make([]byte, 0, int(c.DataSize))
	for len(outBuff) < int(c.DataSize) {
		readSize := blockSize
		if readSize > (int(c.DataSize) - len(outBuff)) {
			readSize = int(c.DataSize) - len(outBuff)
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: pub.NVIndex,
				Name:   *nvName,
				Auth:   tpm2.PasswordAuth([]byte("p@ssw0rd")),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(*nv),
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),
			Offset: uint16(len(outBuff)),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("Calling NV Read: %v", err)
		}
		data := readRsp.Data.Buffer
		outBuff = append(outBuff, data...)
	}

	log.Println(base64.StdEncoding.EncodeToString(outBuff))

	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,

		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
}
