package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

/*
rm -rf myvtpm && mkdir myvtpm  && \
   swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert &&  \
   swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"

*/

const (
	tpmDevice     = "/dev/tpm0"
	emptyPassword = ""
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	nv      = flag.Uint("nv", 0x1500000, "nv to use") //tpm2_nvundefine 0x1500000
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

	getidxCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}
	getidxRsp, err := getidxCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("errpr Calling GetCapability: %v", err)
	}

	tpidx, err := getidxRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		log.Fatalf("error Calling TPMProperties: %v", err)
	}

	idxSize := int(tpidx.TPMProperty[0].Value)
	log.Printf("TPM  TPMPTNVIndexMax %d", idxSize)

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
	log.Printf("TPM TPMPTNVBufferMax %d", blockSize)

	// *****************

	log.Printf("     Load SigningKey and Cert ")
	// read direct from nv template

	token := make([]byte, idxSize) // can't be larger than TPM2_PT_NV_INDEX_MAX
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
				DataSize: uint16(idxSize),
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
