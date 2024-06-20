package main

// go run main.go --mode=read --pcr=1 -v 10 -alsologtostderr
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

var (
	tpmPath = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	mode    = flag.String("mode", "read", "read or extend PCR value")
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

	if *mode == "read" {

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

	} else if *mode == "extend" {
		log.Printf("======= Extend PCR  ========")
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
		_, err = tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(uint32(*pcr)),
				Auth:   tpm2.PasswordAuth(nil),
			},
			Digests: tpm2.TPMLDigestValues{
				Digests: []tpm2.TPMTHA{
					{
						HashAlg: tpm2.TPMAlgSHA256,
						Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			panic(err)
		}

		pcrReadRsp, err = tpm2.PCRRead{
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
}
