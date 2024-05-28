package main

import (
	"encoding/hex"
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

const ()

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
	rwc, err := OpenTPM("127.0.0.1:2321")
	if err != nil {
		log.Fatalf("can't open TPM  %v", err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		},
	}

	pcrReadRsp, err := pcrRead.Execute(rwr)
	if err != nil {
		panic(err)
	}

	for _, d := range pcrReadRsp.PCRValues.Digests {
		fmt.Printf("hex:   %s\n", hex.EncodeToString(d.Buffer))
	}
}
