package main

// go run main.go --mode=read --pcr=1 -v 10 -alsologtostderr
import (
	"encoding/hex"
	"flag"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultRSAExponent = 1<<16 + 1

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	mode    = flag.String("mode", "", "read or extend PCR value")
	pcr     = flag.Int("pcr", -1, "PCR Value to read or increment")
	flush   = flag.String("flush", "transient", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

	if *mode == "" {
		glog.Fatalf("Mode must be either read or increment")
	}
	if *pcr == -1 {
		glog.Fatalf("pcr number must be set")
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(2).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	if *mode == "read" {
		glog.V(2).Infof("======= Print PCR  ========")
		pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
		if err != nil {
			glog.Fatalf("Unable to ReadPCR: %v", err)
		}
		glog.V(2).Infof("PCR(%d) %s", *pcr, hex.EncodeToString(pcrval))

	} else if *mode == "extend" {
		glog.V(2).Infof("======= Extend PCR  ========")
		pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
		if err != nil {
			glog.Fatalf("Unable to ReadPCR: %v", err)
		}
		glog.V(2).Infof("Current PCR(%d) %s", *pcr, hex.EncodeToString(pcrval))

		pcrToExtend := tpmutil.Handle(*pcr)

		err = tpm2.PCRExtend(rwc, pcrToExtend, tpm2.AlgSHA256, pcrval, "")
		if err != nil {
			glog.Fatalf("Unable to Extend PCR: %v", err)
		}

		pcrval, err = tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
		if err != nil {
			glog.Fatalf("Unable to ReadPCR: %v", err)
		}
		glog.V(2).Infof("New PCR(%d) %s", *pcr, hex.EncodeToString(pcrval))

	}
}
