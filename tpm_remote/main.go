package main

import (
	"encoding/hex"
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

/*
on remote, use tpmabrmd:

apt install tpm2-openssl tpm2-tools tpm2-abrmd libtss2-tcti-tabrmd0
socat tcp-listen:2321,fork,reuseaddr system:'tpm2_send --tcti=device'


on local

$ tpm2_pcrread sha256:23  --tcti="cmd:nc 35.202.228.0 2321"
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

$ export TPM2TOOLS_TCTI="cmd:nc 35.202.228.0 2321"
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B


$ go run main.go --tpm-path="35.202.228.0:2321"
    hex:   f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
*/

var (
	tpmPath = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	pcr     = flag.Uint("pcr", 23, "PCR Value to read or extend")
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

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(*pcr),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		panic(err)
	}

	for _, d := range pcrReadRsp.PCRValues.Digests {
		log.Printf("hex:   %s\n", hex.EncodeToString(d.Buffer))
	}

}
