package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	//"github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	keyPassword = "keypwd"
)

var (
	tpmPath    = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	pcr        = flag.Int("pcr", 23, "PCR to seal data to. Must be within [0, 23].")
	sealedFile = flag.String("file", "secret.dat", "Sealed Filename")
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

/*

this sample will seal data and ensure PCR(23) is the same value.

Then it will unseal the data using the pcr value


then it will extend pcr=23

and finally attempt to unseal.  since the pcr value has changed, unseal operation won't work

*/

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

	log.Printf("======= createPrimary ========")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}
	if err != nil {
		log.Fatalf("Error creating primary: %v", err)
	}

	cPrimary, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			log.Fatalf("cleaning up trial session: %v", err)
		}
	}()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(uint(*pcr)),
			},
		},
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyPCR: %v", err)
	}

	// verify the digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	keyTemplate := tpm2.TPMTPublic{
		Type:       tpm2.TPMAlgKeyedHash,
		NameAlg:    tpm2.TPMAlgSHA256,
		AuthPolicy: pgd.PolicyDigest,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: false, // toggle
		},
	}

	data := []byte("secrets")

	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(keyTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM  %v", err)
	}

	aKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	log.Printf("======= Unseal  ========")
	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing policyAuthValue: %v", err)
	}

	unsealresp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: aKey.ObjectHandle,
			Name:   aKey.Name,
			Auth:   sess2,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing unseal: %v", err)
	}

	log.Printf("Unsealed %s", string(unsealresp.OutData.Buffer))

	log.Printf("======= Extend PCR  ========")
	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		panic(err)
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

	pcrReadRspE, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		panic(err)
	}
	for _, d := range pcrReadRspE.PCRValues.Digests {
		log.Printf("New PCR Value:   %s\n", hex.EncodeToString(d.Buffer))
	}

	log.Printf("======= Attempt Unseal ========")
	sess3, cleanup3, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup3()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess3.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing policyAuthValue: %v", err)
	}

	unsealresp3, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: aKey.ObjectHandle,
			Name:   aKey.Name,
			Auth:   sess3,
		},
		// ItemHandle: tpm2.NamedHandle{
		// 	Handle: aKey.ObjectHandle,
		// 	Name:   aKey.Name,
		// },
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing unseal: %v", err)
	}

	log.Printf("Unsealed %s", string(unsealresp3.OutData.Buffer))

}
