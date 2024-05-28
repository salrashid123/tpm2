package main

import (
	"flag"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath    = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	dataToSeal = flag.String("datatoseal", "secret", "data to sign")
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
func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	//rwc, err := tpmutil.OpenTPM(*tpmPath)
	//rwc, err := simulator.GetWithFixedSeedInsecure(1073741825)

	rwc, err := OpenTPM("127.0.0.1:2321")
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary ========")

	// create a primary with auth with a session that is encrypted using the EK

	srkAuth := []byte("mySRK")
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: srkAuth,
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// rsa

	log.Printf("======= create key  ========")

	// create a Key with auth with a password and some data to seal
	// // Use HMAC auth to authorize the rest of the Create commands
	// use the newprimary key

	data := []byte(*dataToSeal)
	auth := []byte("passw0rd")

	createBlobRsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(srkAuth),
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: auth,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create blob %v", err)
	}

	// Load the sealed blob
	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(srkAuth),
		},
		InPrivate: createBlobRsp.OutPrivate,
		InPublic:  createBlobRsp.OutPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create blob %v", err)
	}

	defer func() {
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(rwr); err != nil {
			log.Fatalf("can't close flush blob %v", err)
		}
	}()

	log.Println("Created blob")

	// unseal with standalone session
	log.Println("======= unsealing ========")
	//defer cleanup()

	unsealRsp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   tpm2.PasswordAuth(auth),
		},
	}.Execute(rwr)

	if err != nil {
		log.Fatalf("can't unseal %v", err)
	}

	log.Printf("Unsealed %s\n", string(unsealRsp.OutData.Buffer))
}
