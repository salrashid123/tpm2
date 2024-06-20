package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"os"

	// "github.com/google/go-tpm-tools/simulator"
	// "github.com/google/go-tpm/tpmutil"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	maxInputBuffer = 1024
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "private.pem", "privateKey File")

	ECCSRKHTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

func main() {
	flag.Parse()

	flag.Parse()
	log.Println("======= Init  ========")

	// ************************

	rwc, err := tpmutil.OpenTPM(*tpmPath)
	//rwc, err := simulator.GetWithFixedSeedInsecure(1073741825)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	c, err := os.ReadFile(*in)
	if err != nil {
		log.Fatalf("can't load keys %q: %v", *tpmPath, err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("can't decode keys %q: %v", *tpmPath, err)
	}

	// specify its parent directly
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: key.Parent,
		InPublic:      tpm2.New2B(ECCSRKHTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// now the actual key can get loaded from that parent
	rsaKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		log.Fatalf("can't load  hmacKey : %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	/// ============================ =================================================================================================
	data := []byte("foo")
	digest := sha256.Sum256(data)

	rspSign2, err := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: rsaKey.ObjectHandle,
			Name:   rsaKey.Name,
		},

		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	rsassa2, err := rspSign2.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature from go-tpm-tools key : %s\n", hex.EncodeToString(rsassa2.Sig.Buffer))
}
