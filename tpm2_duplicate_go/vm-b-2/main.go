package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	parentPassword = ""
	ownerPassword  = ""
)

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	newParentPub  = flag.String("new-parent", "new-parent.pub", "New Parents public key")
	newParentPriv = flag.String("new-parent-priv", "new-parent.priv", "New Parents public key")
	dupPub        = flag.String("duppub", "dup.pub", "dup public")
	dupDup        = flag.String("dupdup", "dup.dup", "dup duplicate")
	dupSeed       = flag.String("dupseed", "dup.seed", "dup seed file")
	dataToHMAC    = flag.String("data-to-hmac", "foo", "Data to hmac")
)

func main() {

	flag.Parse()
	log.Println("======= Init  ========")

	rwc, err := tpmutil.OpenTPM(*tpmPath)
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
		CreationPCR: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		},
	}
	if err != nil {
		log.Fatalf("Error creating EK: new_parent.prv%v", err)
	}

	cPrimary, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err := flush.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	log.Printf("Name %s\n", hex.EncodeToString(cPrimary.Name.Buffer))

	log.Println("_---- load -----")

	newParentPubBytes, err := os.ReadFile(*newParentPub)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	newParentPrvBytes, err := os.ReadFile(*newParentPriv)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	pub2, err := tpm2.Unmarshal[tpm2.TPMTPublic](newParentPubBytes)
	if err != nil {
		log.Fatalf(" unmarshal public %q: %v", *tpmPath, err)
	}

	// prv2, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](newParentPrvBytes)
	// if err != nil {
	// 	log.Fatalf(" Unmarshal private  %q: %v", *tpmPath, err)
	// }

	loadCmd := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: newParentPrvBytes,
		},

		InPublic: tpm2.New2B(*pub2),
	}
	loadRsp, err := loadCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}

	// flush parent
	flush := tpm2.FlushContext{FlushHandle: cPrimary.ObjectHandle}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadRsp.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Printf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	log.Println("Import")

	dupPubBytes, err := os.ReadFile(*dupPub)
	if err != nil {
		log.Fatalf("can't read dupPubFile: %v", err)
	}

	dupseedBytes, err := os.ReadFile(*dupSeed)
	if err != nil {
		log.Fatalf("can't read dupSeedFile  %v", err)
	}

	dupdupBytes, err := os.ReadFile(*dupDup)
	if err != nil {
		log.Fatalf("can't read dupDupFile %v", err)
	}

	dupPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](dupPubBytes)
	if err != nil {
		log.Fatalf(" unmarshal public %q: %v", *tpmPath, err)
	}

	importCmd := tpm2.Import{
		ParentHandle: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		ObjectPublic: tpm2.New2B(*dupPub),
		Duplicate: tpm2.TPM2BPrivate{
			Buffer: dupdupBytes,
		},
		InSymSeed: tpm2.TPM2BEncryptedSecret{
			Buffer: dupseedBytes,
		},
	}
	importResp, err := importCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't run import dup %q: %v", *tpmPath, err)
	}

	loadkCmd := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		InPrivate: importResp.OutPrivate,
		InPublic:  tpm2.New2B(*dupPub),
	}
	loadkRsp, err := loadkCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadkRsp.ObjectHandle,
			Name:   loadkRsp.Name,
		},
		PersistentHandle: 0x81000001,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't childPub failed for write%v\n", err)
	}

	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("aaa start hmac session %q: %v", *tpmPath, err)
	}
	defer func() {
		_ = sasCloser()
	}()
	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: loadkRsp.ObjectHandle,
			Name:   loadkRsp.Name,
			Auth:   sas,
		},
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(""),
		},
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		log.Fatalf("can't start hmac %q: %v", *tpmPath, err)
	}

	maxInputBuffer := 1024
	data := []byte(*dataToHMAC)
	authHandle := tpm2.AuthHandle{
		Name:   loadkRsp.Name,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth([]byte("")),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			log.Fatalf("cant do sequence update on hmac %q: %v", *tpmPath, err)
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		log.Fatalf("can't complete hmac %q: %v", *tpmPath, err)
	}

	log.Printf("calculated hmac:  %s\n", hex.EncodeToString(rspSC.Result.Buffer))
}
