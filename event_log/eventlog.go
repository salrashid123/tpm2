package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath      = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	eventLogFile = flag.String("eventLogFile", "binary_bios_measurements", "binary log")
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

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	data, err := os.ReadFile(*eventLogFile)
	if err != nil {
		panic(err)
	}

	serverPlatformAttestationParameter := &attest.PlatformParameters{
		EventLog: data,
	}

	el, err := attest.ParseEventLog(serverPlatformAttestationParameter.EventLog)
	if err != nil {
		fmt.Printf("Quote Parsing EventLog Failed:  %v", err)
		return
	}

	for _, e := range el.Events(attest.HashSHA256) {
		fmt.Printf("Event Index: %d %s\n", e.Index, e.Type)
		//fmt.Printf("   Event: %s\n", string(e.Data))

		// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
		if e.Type != 0x00000003 { //"EV_NO_ACTION"
			aesKey, err := tpm2.PCRExtend{
				PCRHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMHandle(uint32(e.Index)),
					Auth:   tpm2.PasswordAuth(nil),
				},
				Digests: tpm2.TPMLDigestValues{
					Digests: []tpm2.TPMTHA{
						{
							HashAlg: tpm2.TPMAlgSHA256,
							Digest:  e.Digest,
						},
					},
				},
			}.Execute(rwr)
			if err != nil {
				log.Fatalf("can't execute pecrevent %v", err)
			}

			fmt.Println(aesKey)
		}

	}

}
