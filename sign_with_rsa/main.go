package main

import (
	"flag"

	"crypto/sha256"
	"encoding/base64"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const ()

// Signs some data using key data at handle 0x81010002

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	tpmPath   = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	keyHandle = flag.Int("handle", 0x81010002, "Handle value")
)

func main() {

	flag.Parse()
	glog.V(2).Infof("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
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

	glog.V(2).Infof("%d handles flushed\n", totalHandles)

	//handle := tpmutil.Handle(0x81010002)

	handle := tpmutil.Handle(*keyHandle)

	dataToSeal := []byte("secret")

	digest := sha256.Sum256(dataToSeal)
	sig, err := tpm2.Sign(rwc, handle, "", digest[:], &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		glog.Fatalf("Error Signing: %v", err)
	}
	glog.V(2).Infof("Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

}
