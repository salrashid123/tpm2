package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"io/ioutil"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

var handleNames = map[string][]tpm2.HandleType{
	"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    {tpm2.HandleTypeLoadedSession},
	"saved":     {tpm2.HandleTypeSavedSession},
	"transient": {tpm2.HandleTypeTransient},
}

var (
	tpmPath              = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	importSigningKeyFile = flag.String("importSigningKeyFile", "", "Path to the importSigningKeyFile blob).")
	bindPCRValues        = flag.String("bindPCRValues", "", "PCR Value to bind session to, comma separated list of PCRs 0->23")
	mode                 = flag.String("mode", "import", "import or sign")
	pub                  = flag.String("pub", "pub.dat", "public key")
	priv                 = flag.String("priv", "priv.dat", "private key")
	stringToSign         = flag.String("stringToSign", "foo", "data to sign")
	flush                = flag.String("flush", "transient", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Printf("can't close TPM %q: %v", tpmPath, err)
			os.Exit(1)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Printf("getting handles: %v", err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Printf("flushing handle 0x%x: %v", handle, err)
				os.Exit(1)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	var pcrList = []int{}

	if *bindPCRValues != "" {
		for _, i := range strings.Split(*bindPCRValues, ",") {
			j, err := strconv.Atoi(i)
			if err != nil {
				panic(err)
			}
			pcrList = append(pcrList, j)
		}
	}
	for _, i := range pcrList {
		fmt.Println("======= Print PCR  ========")
		pcr23, err := tpm2.ReadPCR(rwc, i, tpm2.AlgSHA256)
		if err != nil {
			fmt.Printf("Unable to ReadPCR: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Using PCR: %i %s\n", i, hex.EncodeToString(pcr23))
	}

	if *mode == "import" {
		err := importSigningKey(rwc, *importSigningKeyFile, *pub, *priv, *stringToSign, pcrList)
		if err != nil {
			fmt.Printf("Error importSigningKey: %v\n", err)
			return
		}
	} else if *mode == "sign" {
		err := sign(rwc, *pub, *priv, *stringToSign, pcrList)
		if err != nil {
			fmt.Printf("Error sign: %v\n", err)
			return
		}
	}

}

func sign(rwc io.ReadWriteCloser, pubFile string, privFile string, dat string, lbindPCRValue []int) (retErr error) {

	pubBytes, err := os.ReadFile(pubFile)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	privBytes, err := os.ReadFile(privFile)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	fmt.Println("======= Loading EndorsementKeyRSA ========")
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer ek.Close()

	sess2, err := client.NewEKSession(rwc)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer sess2.Close()
	authcmd, err := sess2.Auth()
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	fmt.Println("======= Generating Signature ========")
	var signed *tpm2.Signature

	kh, _, err := tpm2.LoadUsingAuth(rwc, ek.Handle(), authcmd, pubBytes, privBytes)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer tpm2.FlushContext(rwc, kh)
	data := []byte(dat)
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)

	khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, data, tpm2.HandleOwner)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	fmt.Printf("TPM based Hash %s\n", base64.StdEncoding.EncodeToString(khDigest))

	if len(lbindPCRValue) > 0 {
		fmt.Println("======= Generating Signature with PolicyPCR ========")

		session, _, err := tpm2.StartAuthSession(
			rwc,
			/*tpmkey=*/ tpm2.HandleNull,
			/*bindkey=*/ tpm2.HandleNull,
			/*nonceCaller=*/ make([]byte, 32),
			/*encryptedSalt=*/ nil,
			/*sessionType=*/ tpm2.SessionPolicy,
			/*symmetric=*/ tpm2.AlgNull,
			/*authHash=*/ tpm2.AlgSHA256)
		if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, lbindPCRValue}); err != nil {
			return fmt.Errorf(err.Error())
		}

		signed, err = tpm2.SignWithSession(rwc, session, kh, "", d[:], khValidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			return fmt.Errorf(err.Error())
		}
	} else {
		fmt.Println("======= Generating Signature without PolicyPCR ========")
		signed, err = tpm2.Sign(rwc, kh, "", d[:], khValidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			return fmt.Errorf(err.Error())
		}
	}

	sig := base64.StdEncoding.EncodeToString(signed.RSA.Signature)
	fmt.Printf("Test Signature: %s\n", sig)
	return
}

func importSigningKey(rwc io.ReadWriteCloser, importSigningKeyFile string, pubFile string, privFile string, dat string, lbindPCRValue []int) (retErr error) {
	fmt.Println("======= Init importSigningKey ========")

	fmt.Println("======= Loading EndorsementKeyRSA ========")
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer ek.Close()

	fmt.Println("======= Loading sealedkey ========")
	importblob := &pb.ImportBlob{}
	importdata, err := ioutil.ReadFile(importSigningKeyFile)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	err = proto.Unmarshal(importdata, importblob)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	sess, err := client.NewEKSession(rwc)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer sess.Close()
	auth, err := sess.Auth()
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	private, err := tpm2.Import(rwc, ek.Handle(), auth, importblob.PublicArea, importblob.Duplicate, importblob.EncryptedSeed, nil, nil)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	// now write the pub/priv to file

	puF, err := os.Create(pubFile)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer puF.Close()

	_, err = puF.Write(importblob.PublicArea)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	privF, err := os.Create(*priv)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	defer privF.Close()
	_, err = privF.Write(private)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}
