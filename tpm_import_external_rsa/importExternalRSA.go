package main

/*
  Import a PEM key and file to TPM

  This utility is approximately the equivalent of the following TPM2 commands:

	To import PEM file
	  openssl genrsa -out private.pem 2048
	  openssl rsa -in private.pem -outform PEM -pubout -out public.pem


    ## using tpm2_tools
	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256  -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81010003

*/

import (
	"flag"
	"fmt"
	"os"

	//"fmt"

	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"log"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword = ""
)

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
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

	tpmPath   = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pemFile   = flag.String("pemFile", "client.key", "Private key PEM format file")
	keyHandle = flag.Int("handle", 0x81010002, "Handle value")
	evict     = flag.Bool("evict", false, "Evict control to keyHandle")
	keyPub    = flag.String("keyPub", "key.pub", "Path to save the KeyFileContext pub.")
	keyPriv   = flag.String("keyPriv", "key.priv", "Path to save the KeyFileContext priv.")
	mode      = flag.String("mode", "create", "create or load")
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("    can't open TPM %s: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("     can't close TPM %s: %v", *tpmPath, err)
		}
	}()

	log.Printf("======= Flushing Transient Handles ========")
	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := client.Handles(rwc, handleType)
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

	if *mode == "create" {
		log.Printf("======= Import ======= ")
		if *pemFile == "" {
			log.Fatalf("Specify _either_ serviceAccountFile= or pemFile=")
		}

		log.Printf("======= Init ========")

		var pv *rsa.PrivateKey

		data, err := os.ReadFile(*pemFile)

		if err != nil {
			log.Fatalf("     Unable to read serviceAccountFile %v", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatalf("     Failed to decode PEM block containing the key %v", err)
		}
		pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("     Failed to parse PEM block containing the key %v", err)
		}
		pv = pvp.(*rsa.PrivateKey)
		rp := tpm2.Public{
			Type:       tpm2.AlgRSA,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagUserWithAuth | tpm2.FlagSign, // | tpm2.FlagDecrypt,
			RSAParameters: &tpm2.RSAParams{
				KeyBits:     2048,
				ExponentRaw: uint32(pv.PublicKey.E),
				ModulusRaw:  pv.PublicKey.N.Bytes(),
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgRSASSA,
					Hash: tpm2.AlgSHA256,
				},
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
		if err != nil {
			log.Fatalf("     Private reading name: %s", err)
		}

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

		log.Printf("     SavePub (%s) ========", *keyPub)

		err = os.WriteFile(*keyPub, pubArea, 0644)
		if err != nil {
			log.Fatalf("     ContextSave failed for key.bin: %v", err)
		}
		log.Printf("     SavePriv (%s) ========", *keyPriv)

		err = os.WriteFile(*keyPriv, iprivate, 0644)
		if err != nil {
			log.Fatalf("     ContextSave failed for key.bin: %v", err)
		}
		pHandle := tpmutil.Handle(*keyHandle)
		if *evict {
			log.Printf("======= EvictControl ======== ")

			log.Printf("     Evicting Persistent Handle at %v ", fmt.Sprintf("%x", *keyHandle))

			err = tpm2.EvictControl(rwc, emptyPassword, tpm2.HandleOwner, pHandle, pHandle)
			if err != nil {
				glog.Infof("     Unable evict persistentHandle: %v ", err)
			}
		}

		err = tpm2.EvictControl(rwc, emptyPassword, tpm2.HandleOwner, pH, pHandle)
		if err != nil {
			log.Fatalf("     Unable to set persistentHandle: %v", err)
		}
		defer tpm2.FlushContext(rwc, pHandle)
		log.Printf("     key persisted")
		tpm2.FlushContext(rwc, pH)
	}

	log.Printf("     LoadkeyPub (%s) ========", *keyPub)
	pubArea, err := os.ReadFile(*keyPub)
	if err != nil {
		log.Fatalf("     failed to load key public: %v", err)
	}

	log.Printf("     LoadkeyPriv (%s) ========", *keyPriv)
	iprivate, err := os.ReadFile(*keyPriv)
	if err != nil {
		log.Fatalf("     failed to load key private: %v", err)
	}
	pH, name, err := tpm2.Load(rwc, kh, emptyPassword, pubArea, iprivate)
	if err != nil {
		log.Fatalf("     Duplicate encoding error: %s", err)
	}
	defer tpm2.FlushContext(rwc, pH)
	log.Printf("     Loaded Import Blob transient handle [0x%X], Name: %v", pH, hex.EncodeToString(name))

	dataToSign := []byte("secret")

	khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSign, tpm2.HandleOwner)
	if err != nil {
		log.Fatalf("Hash failed unexpectedly: %v", err)
		return
	}

	sig, err := tpm2.Sign(rwc, pH, emptyPassword, khDigest[:], khValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		log.Fatalf("Error Signing: %v", err)
	}

	log.Printf("Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

}
