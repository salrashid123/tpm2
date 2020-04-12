package main

/*
  Import a PEM key and file to TPM

  This utility is approximately the equivalent of the following TPM2 commands:

	To import PEM file
	  openssl genrsa -out private.pem 2048


	openssl rsa -in private.pem -outform PEM -pubout -out public.pem


	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81010002


	go run main.go --pemFile private.pem --primaryFileName=primary.bin --keyFileName=key.bin --logtostderr=1 -v 10
*/

import (
	"flag"
	//"fmt"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword = ""
)

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
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

	tpmPath         = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pemFile         = flag.String("pemFile", "client.key", "Private key PEM format file")
	primaryFileName = flag.String("primaryFileName", "", "Path to save the PrimaryContext.")
	keyFileName     = flag.String("keyFileName", "", "Path to save the KeyFileContext.")
)

func main() {

	flag.Parse()

	if *pemFile == "" {
		log.Fatalf("Specify _either_ serviceAccountFile= or pemFile=")
	}

	log.Printf("======= Init ========")

	var pv *rsa.PrivateKey
	if *pemFile != "" {
		data, err := ioutil.ReadFile(*pemFile)

		if err != nil {
			log.Fatalf("     Unable to read serviceAccountFile %v", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatalf("     Failed to decode PEM block containing the key %v", err)
		}
		pv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("     Failed to parse PEM block containing the key %v", err)
		}
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("    can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("     %v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	log.Printf("======= Flushing Transient Handles ========")
	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
		if err != nil {
			log.Fatalf("    getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				log.Fatalf("    flushing handle 0x%x: %v", handle, err)
			}
			log.Printf("    Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	log.Printf("    %d handles flushed\n", totalHandles)
	// pcrList := []int{23}
	// pcrval, err := tpm2.ReadPCR(rwc, pcr, tpm2.AlgSHA256)
	// if err != nil {
	// 	log.Fatalf("     Unable to  ReadPCR : %v", err)
	// }
	// log.Printf("     PCR %v Value %v ", pcr, hex.EncodeToString(pcrval))

	// pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	// but for now, just no selection
	pcrSelection23 := tpm2.PCRSelection{}

	kh, pub, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection23, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		log.Fatalf("     CreatePrimary Failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)
	log.Printf("    Primary KeySize %v", pub.(*rsa.PublicKey).Size())

	// reread the pub eventhough tpm2.CreatePrimary* gives pub
	tpmkPub, name, _, err := tpm2.ReadPublic(rwc, kh)
	if err != nil {
		log.Fatalf("     ReadPublic failed: %s", err)
	}

	p, err := tpmkPub.Key()
	if err != nil {
		log.Fatalf("      tpmPub.Key() failed: %s", err)
	}
	log.Printf("     tpmPub Size(): %d", p.(*rsa.PublicKey).Size())

	b, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		log.Fatalf("     Unable to convert pub: %v", err)
	}

	kPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	log.Printf("     Pub Name: %v", hex.EncodeToString(name))
	log.Printf("     PubPEM: \n%v", string(kPubPEM))

	log.Printf("     ContextSave (%s) ========", *primaryFileName)
	ekhBytes, err := tpm2.ContextSave(rwc, kh)
	if err != nil {
		log.Fatalf("     ContextSave failed for primaryFileName: %v", err)
	}
	err = ioutil.WriteFile("primary.bin", ekhBytes, 0644)
	if err != nil {
		log.Fatalf("     ContextSave failed for primaryFileName: %v", err)
	}
	tpm2.FlushContext(rwc, kh)

	log.Printf("     ContextLoad (%s) ========", *primaryFileName)
	khBytes, err := ioutil.ReadFile(*primaryFileName)
	if err != nil {
		log.Fatalf("     ContextLoad failed for primaryFileName: %v", err)
	}
	kh, err = tpm2.ContextLoad(rwc, khBytes)
	if err != nil {
		log.Fatalf("     ContextLoad failed for primaryFileName: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)

	log.Printf("======= Import ======= ")

	rp := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagUserWithAuth | tpm2.FlagSign, // | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			KeyBits:     2048,
			ExponentRaw: uint32(pv.PublicKey.E),
			ModulusRaw:  pv.PublicKey.N.Bytes(),
		},
	}
	rpriv := tpm2.Private{
		Type:      tpm2.AlgRSA,
		Sensitive: pv.Primes[0].Bytes(),
	}

	pubArea, err := rp.Encode()
	if err != nil {
		log.Fatalf("     Public encoding error: %s", err)
	}

	decImported, err := tpm2.DecodePublic(pubArea)
	if err != nil {
		log.Fatalf("     DecodePublic returned error: %v", err)
	}
	importedPubName, err := decImported.Name()
	log.Printf("     Imported Public digestValue: %v", hex.EncodeToString(importedPubName.Digest.Value))

	privArea, err := rpriv.Encode()
	if err != nil {
		log.Fatalf("     Private encoding error: %s", err)
	}

	duplicate, err := tpmutil.Pack(tpmutil.U16Bytes(privArea))
	if err != nil {
		log.Fatalf("     Duplicate encoding error: %s", err)
	}

	emptyAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}

	iprivate, err := tpm2.Import(rwc, kh, emptyAuth, pubArea, duplicate, nil, nil, nil)
	if err != nil {
		log.Fatalf("     Unable to Import Private: %v", err)
	}

	pH, name, err := tpm2.Load(rwc, kh, emptyPassword, pubArea, iprivate)
	if err != nil {
		log.Fatalf("     Duplicate encoding error: %s", err)
	}
	defer tpm2.FlushContext(rwc, pH)
	log.Printf("     Loaded Import Blob transient handle [0x%X], Name: %v", pH, hex.EncodeToString(name))

	log.Printf("     ContextSave (%s) ========", *keyFileName)
	pHBytes, err := tpm2.ContextSave(rwc, pH)
	if err != nil {
		log.Fatalf("     ContextSave failed for key.bin: %v", err)
	}
	err = ioutil.WriteFile(*keyFileName, pHBytes, 0644)
	if err != nil {
		log.Fatalf("     ContextSave failed for key.bin: %v", err)
	}
	tpm2.FlushContext(rwc, pH)

	log.Printf("     ContextLoad (%s) ========", *keyFileName)
	pHBytes, err = ioutil.ReadFile(*keyFileName)
	if err != nil {
		log.Fatalf("     ContextLoad failed for importedKey: %v", err)
	}
	pH, err = tpm2.ContextLoad(rwc, pHBytes)
	if err != nil {
		log.Fatalf("     ContextLoad failed for importedKey: %v", err)
	}
	defer tpm2.FlushContext(rwc, pH)

	// log.Printf("======= EvictControl ======== ")

	// log.Printf("     Evicting Persistent Handle at %v ", fmt.Sprintf("%x", *keyHandle))
	// pHandle := tpmutil.Handle(*keyHandle)

	// err = tpm2.EvictControl(rwc, emptyPassword, tpm2.HandleOwner, pHandle, pHandle)
	// if err != nil {
	// 	glog.Infof("     Unable evict persistentHandle: %v ", err)
	// }

	// err = tpm2.EvictControl(rwc, emptyPassword, tpm2.HandleOwner, pH, pHandle)
	// if err != nil {
	// 	log.Fatalf("     Unable to set persistentHandle: %v", err)
	// }
	// defer tpm2.FlushContext(rwc, pHandle)
	// log.Printf("     key persisted")

	dataToSign := []byte("secret")
	digest := sha256.Sum256(dataToSign)
	sig, err := tpm2.Sign(rwc, pH, emptyPassword, digest[:], &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		log.Fatalf("Error Signing: %v", err)
	}

	log.Printf("Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

	if err := rsa.VerifyPKCS1v15(pv.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], []byte(sig.RSA.Signature)); err != nil {
		log.Fatalf("Signature verification failed: %v", err)
	}

}
