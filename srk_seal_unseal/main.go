package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/golang/protobuf/proto"
	//"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type SealCurrent struct{ tpm2.PCRSelection }

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	tpmPath    = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcr        = flag.Int("pcr", 23, "PCR to seal data to. Must be within [0, 23].")
	secret     = flag.String("secret", "6cefd64524ee24a6bdce2501e67fze8b", "Secret to seal to TPM")
	sealedFile = flag.String("file", "secret.dat", "Sealed Filename")
)

func main() {
	flag.Parse()

	if *pcr < 0 || *pcr > 23 {
		fmt.Fprintf(os.Stderr, "Invalid flag 'pcr': value %d is out of range", *pcr)
		os.Exit(1)
	}

	err := run(*pcr, *tpmPath, *secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(pcr int, tpmPath string, secret string) (retErr error) {

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			log.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				log.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			log.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	log.Printf("%d handles flushed\n", totalHandles)

	srk, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		log.Fatalf("can't create srk from template: %v", err)
	}
	defer srk.Close()

	log.Printf("Loaded SRK: %v", srk.Name())

	pcrList := []int{pcr}
	pcrToExtend := tpmutil.Handle(pcr)
	log.Printf("PCR %v handle: %v", pcrList, pcrToExtend)

	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{pcr}}
	sOpt := client.SealOpts{
		Current: sel}

	sealed, err := srk.Seal([]byte(secret), sOpt)
	if err != nil {
		log.Fatalf("failed to seal: %v", err)
	}
	out, err := proto.Marshal(sealed)
	if err != nil {
		log.Fatalf("Failed to encode SealedBytes: %v", err)
	}
	if err := ioutil.WriteFile(*sealedFile, out, 0644); err != nil {
		log.Fatalf("Failed to write SealedBytes: %v", err)
	}

	log.Printf("Key material sealed on file [%v] with PCR: %v", sealedFile, pcr)

	u, err := srk.Unseal(sealed, client.UnsealOpts{
		CertifyCurrent: sel,
	})
	if err != nil {
		log.Fatalf("Failed to unseal: %v", err)
	}
	log.Printf("Unsealed %s", u)
	return
}
