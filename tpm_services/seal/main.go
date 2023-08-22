package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"log"
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/client"

	//"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

var (
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
)

func main() {
	flag.Parse()

	// on client create SKR cert
	rwc, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer rwc.Close()

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

	// ek, err := client.EndorsementKeyRSA(rwc)
	// if err != nil {
	// 	log.Fatalf("failed to create storage root key: %v", err)
	// }

	// seal to endorsement not supported yet
	//srk, err := client.EndorsementKeyECC(rwc)
	srk, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		log.Fatalf("failed to create storage root key: %v", err)
	}

	// send srk to server
	// on server use SRK to seal secret to tpm value and pcr value

	sealedSecret := []byte("secret password")
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}

	// seal on server
	pcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		log.Fatalf("failed to create storage root key: %v", err)
	}
	pcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}
	sealedBlob, err := srk.Seal([]byte(sealedSecret), client.SealOpts{Target: pcrs})
	if err != nil {
		log.Fatalf("failed to seal to SRK: %v", err)
	}

	// send sealedBlob to client
	// unseal on client
	output, err := srk.Unseal(sealedBlob, client.UnsealOpts{CertifyCurrent: sel})
	if err != nil {
		log.Fatalf("failed to unseal blob: %v", err)
	}
	// TODO: use unseal output.
	fmt.Println(string(output))
}

func getPCRMap(algo tpm.HashAlgo) (map[uint32][]byte, []byte, error) {

	pcrMap := make(map[uint32][]byte)
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm.HashAlgo_SHA1 {
		hsh = sha1.New()
	}
	if algo == tpm.HashAlgo_SHA256 {
		hsh = sha256.New()
	}
	if algo == tpm.HashAlgo_SHA1 || algo == tpm.HashAlgo_SHA256 {
		for _, v := range strings.Split(*expectedPCRMapSHA256, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(entry[1])
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint32(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	if len(pcrMap) == 0 {
		return nil, nil, fmt.Errorf(" PCRMap is null")
	}
	return pcrMap, hsh.Sum(nil), nil
}
