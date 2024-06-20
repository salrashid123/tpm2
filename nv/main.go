package main

import (
	"flag"
	"io"
	"log"
	"net"
	"slices"

	//"github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	keyPassword = "keypwd"
)

var (
	tpmPath = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	nv      = flag.Uint("nv", 0x1500000, "nv to use")
	nvdata  = flag.String("nvdata", "foo", "nv data")
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

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		// Auth: tpm2.TPM2BAuth{
		// 	Buffer: []byte("p@ssw0rd"),
		// },
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
				DataSize: 4,
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

	prewrite := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})), //tpm2.PasswordAuth([]byte("p@ssw0rd")),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: []byte("fooo"),
		},
		Offset: 0,
	}
	if _, err := prewrite.Execute(rwr); err != nil {
		log.Fatalf("Calling TPM2_NV_Write: %v", err)
	}

	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: pub.NVIndex,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	log.Printf("Name: %x", readPubRsp.NVName.Buffer)

	readRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})), //tpm2.PasswordAuth([]byte("")), //tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte("p@ssw0rd"))),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   readPubRsp.NVName,
		},
		Size: 4,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Calling Read: %v", err)
	}
	log.Printf("Name: %s", string(readRsp.Data.Buffer))
}
