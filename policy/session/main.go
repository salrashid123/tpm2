package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	emptyPassword = ""
	objPassword   = "bar"
	srkPassword   = "foo"
	pcrBank       = 23
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	srkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
)

func main() {

	flag.Parse()
	log.Println("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
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

	pcrList := []int{pcrBank}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	log.Printf("======= createPrimary ========")

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, srkPassword, srkTemplate)
	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, pkh)
	log.Printf("======= createPrimary completed ========")

	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	// add a policy to pcr=23
	pcrval, err := tpm2.ReadPCRs(rwc, pcrSelection)
	if err != nil {
		log.Fatalf("Unable to ReadPCR: %v", err)
	}

	var expectedVal []byte
	for _, pcr := range pcrSelection.PCRs {
		expectedVal = append(expectedVal, pcrval[pcr]...)
	}

	expectedDigest := sha256.Sum256(expectedVal)
	log.Printf("Starting PCR Digest %s", hex.EncodeToString(expectedDigest[:]))
	// An empty expected digest means that digest verification is skipped.
	if err := tpm2.PolicyPCR(rwc, sessCreateHandle, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
		log.Fatalf("unable to bind PCRs to auth policy: %v", err)
	}

	err = tpm2.PolicyPassword(rwc, sessCreateHandle)
	if err != nil {
		log.Fatalf("Unable to create PolicyPassword : %v", err)
	}

	policyVal, err := tpm2.PolicyGetDigest(rwc, sessCreateHandle)
	if err != nil {
		log.Fatalf("Unable to create PolicyPassword : %v", err)
	}
	log.Printf("Policy Hash: %v", hex.EncodeToString(policyVal))
	if err := tpm2.FlushContext(rwc, sessCreateHandle); err != nil {
		log.Fatalf("FlushContext() failed: %v", err)
	}

	data := []byte("foooo")

	// Encrypt

	priv, pub, err := tpm2.Seal(rwc, pkh, srkPassword, objPassword, policyVal, data)
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	tpm2.FlushContext(rwc, sessCreateHandle)

	pcr23Val, err := tpm2.ReadPCR(rwc, pcrBank, tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to ReadPCR: %v", err)
	}
	expectedDigest = sha256.Sum256(pcr23Val)

	// Extend PCR=23
	// err = tpm2.PCRExtend(rwc, pcrBank, tpm2.AlgSHA256, expectedDigest[:], emptyPassword)
	// if err != nil {
	// 	log.Fatalf("Unable to Extend PCR: %v", err)
	// }

	pcrval, err = tpm2.ReadPCRs(rwc, pcrSelection)
	if err != nil {
		log.Fatalf("Unable to ReadPCR: %v", err)
	}

	var endingexpectedVal []byte
	for _, pcr := range pcrSelection.PCRs {
		endingexpectedVal = append(endingexpectedVal, pcrval[pcr]...)
	}

	expectedDigest = sha256.Sum256(endingexpectedVal)
	log.Printf("Ending PCR Digest %s", hex.EncodeToString(expectedDigest[:]))

	// DECRYPT

	objHandle, _, err := tpm2.Load(rwc, pkh, srkPassword, pub, priv)
	if err != nil {
		log.Fatalf("Unable to create Load : %v", err)
	}

	sessUnseaHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessUnseaHandle)

	if err := tpm2.PolicyPCR(rwc, sessUnseaHandle, expectedDigest[:], pcrSelection); err != nil {
		log.Fatalf("unable to bind PCRs to auth policy: %v", err)
	}

	err = tpm2.PolicyPassword(rwc, sessUnseaHandle)
	if err != nil {
		log.Fatalf("Unable to create PolicyPassword : %v", err)
	}

	decrypted, err := tpm2.UnsealWithSession(rwc, sessUnseaHandle, objHandle, objPassword)
	if err != nil {
		log.Fatalf("DecryptSymmetric failed: %s", err)
	}

	log.Printf("Decrypted %s", string(decrypted))

}
