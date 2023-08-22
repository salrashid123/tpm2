package main

import (
	"crypto/rand"
	"flag"
	"io"
	"log"

	"encoding/base64"
	"encoding/hex"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	emptyPassword   = ""
	defaultPassword = "\x01\x02\x03\x04"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	symKeyParams = tpm2.Public{
		Type:    tpm2.AlgSymCipher,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagSign | tpm2.FlagUserWithAuth |
			tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
		SymCipherParameters: &tpm2.SymCipherParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
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

	pcrList := []int{}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	log.Printf("======= createPrimary ========")

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, pkh)

	log.Printf("======= CreateKey ========")

	authCommandCreateAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(defaultPassword)}

	symPriv, symPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, pkh, pcrSelection, authCommandCreateAuth, defaultPassword, symKeyParams)
	if err != nil {
		log.Fatalf("Create SymKey failed: %s", err)
	}
	log.Printf("symPub: %v,", hex.EncodeToString(symPub))
	log.Printf("symPriv: %v,", hex.EncodeToString(symPriv))

	tPub, err := tpm2.DecodePublic(symPub)
	if err != nil {
		log.Fatalf("Error DecodePublic AK %v", tPub)
	}

	authCommandCreateAuth2 := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(defaultPassword)}

	symkeyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, pkh, authCommandCreateAuth2, symPub, symPriv)
	defer tpm2.FlushContext(rwc, symkeyHandle)
	if err != nil {
		log.Fatalf("Load symkh failed: %s", err)
	}
	log.Printf("SYM keyName: %v,", hex.EncodeToString(keyName))

	data := []byte("foooo")
	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, iv)

	encrypted, err := tpm2.EncryptSymmetric(rwc, defaultPassword, symkeyHandle, iv, data)
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	log.Printf("Encrypted %s", base64.StdEncoding.EncodeToString(encrypted))

	decrypted, err := tpm2.DecryptSymmetric(rwc, defaultPassword, symkeyHandle, iv, encrypted)
	if err != nil {
		log.Fatalf("DecryptSymmetric failed: %s", err)
	}

	log.Printf("Decrypted %s", string(decrypted))

}
