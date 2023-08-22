package main

import (
	"flag"

	"encoding/base64"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"

	//"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const ()

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

	glog.V(2).Infof("%d handles flushed\n", totalHandles)

	//handle := tpmutil.Handle(0x81010002)

	handle := tpmutil.Handle(*keyHandle)

	dataToSeal := []byte("meet me at...")

	encrypted, err := tpm2.RSAEncrypt(rwc, handle, dataToSeal, &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}, "label")
	if err != nil {
		glog.Fatalf("Error Encrypting: %v", err)
	}

	kk := base64.RawStdEncoding.EncodeToString(encrypted)

	glog.V(2).Infof("Encrypted Data %v", kk)

	decrypted, err := tpm2.RSADecrypt(rwc, handle, "", encrypted, &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}, "label")
	if err != nil {
		glog.Fatalf("Error Decrypting: %v", err)
	}
	glog.V(2).Infof("Decrypted Data %v", string(decrypted))
}
