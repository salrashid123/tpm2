package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"

	"io/ioutil"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	pb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultRSAExponent = 1<<16 + 1

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	tpmPath              = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	importSigningKeyFile = flag.String("importSigningKeyFile", "", "Path to the importSigningKeyFile blob).")
	keyHandleOutputFile  = flag.String("keyHandleOutputFile", "key.dat", "Filename to save the loaded keyHandle.")
	bindPCRValue         = flag.Int("bindPCRValue", -1, "PCR Value to bind session to")
	flush                = flag.String("flush", "transient", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

	if *importSigningKeyFile == "" {
		glog.Fatalf("importSigningKeyFile must be set")
	}
	err := importSigningKey(*tpmPath, *importSigningKeyFile, *keyHandleOutputFile, *bindPCRValue)
	if err != nil {
		glog.Fatalf("Error createSigningKeyImportBlob: %v\n", err)
	}

}

func importSigningKey(tpmPath string, importSigningKeyFile string, keyHandleOutputFile string, bindPCRValue int) (retErr error) {
	glog.V(2).Infof("======= Init importSigningKey ========")

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := tpm2tools.Handles(rwc, handleType)
		if err != nil {
			return fmt.Errorf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				return fmt.Errorf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(2).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	if bindPCRValue >= 0 && bindPCRValue <= 23 {
		glog.V(2).Infof("======= Print PCR  ========")
		pcr23, err := tpm2.ReadPCR(rwc, bindPCRValue, tpm2.AlgSHA256)
		if err != nil {
			glog.Fatalf("Unable to ReadPCR: %v", err)
		}
		glog.V(2).Infof("PCR: %i %s", bindPCRValue, hex.Dump(pcr23))
	}
	glog.V(2).Infof("======= Loading EndorsementKeyRSA ========")
	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		return fmt.Errorf("Unable to get EndorsementKeyRSA: %v", err)
	}
	defer ek.Close()

	glog.V(2).Infof("======= Loading sealedkey ========")
	importblob := &pb.ImportBlob{}
	importdata, err := ioutil.ReadFile(importSigningKeyFile)
	if err != nil {
		glog.Fatalf("error reading sealed.dat: ", err)
	}
	err = proto.Unmarshal(importdata, importblob)
	if err != nil {
		glog.Fatal("Unmarshal error: ", err)
	}

	glog.V(2).Infof("======= Loading ImportSigningKey ========")
	key, err := ek.ImportSigningKey(importblob)
	defer key.Close()
	if err != nil {
		glog.Fatalf("error ImportSigningKey: ", err)
	}

	glog.V(10).Infof("======= Saving Key Handle========")
	keyHandle := key.Handle()
	defer key.Close()
	keyBytes, err := tpm2.ContextSave(rwc, keyHandle)
	if err != nil {
		glog.Fatalf("ContextSave failed for keyHandle: %v", err)
	}
	err = ioutil.WriteFile(keyHandleOutputFile, keyBytes, 0644)
	if err != nil {
		glog.Fatalf("FileSave ContextSave failed for keyBytes: %v", err)
	}
	tpm2.FlushContext(rwc, keyHandle)

	glog.V(10).Infof("======= Loading Key Handle ========")
	keyBytes, err = ioutil.ReadFile(keyHandleOutputFile)
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}
	var kh tpmutil.Handle
	kh, err = tpm2.ContextLoad(rwc, keyBytes)
	if err != nil {
		glog.Fatalf("ContextLoad failed for kh: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)

	glog.V(2).Infof("======= Signing Data with Key Handle ========")

	data := []byte("foobar")
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)

	session, _, err := tpm2.StartAuthSession(
		rwc,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, 32),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("StartAuthSession failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, session)

	var signed *tpm2.Signature

	if bindPCRValue >= 0 && bindPCRValue <= 23 {
		if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, []int{bindPCRValue}}); err != nil {
			glog.Fatalf("PolicyPCR failed: %v", err)
		}
		signed, err = tpm2.SignWithSession(rwc, session, kh, "", d[:], &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			glog.Fatalf("google: Unable to Sign wit TPM: %v", err)
		}
	} else {
		signed, err = tpm2.Sign(rwc, kh, "", d[:], &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			glog.Fatalf("google: Unable to Sign wit TPM: %v", err)
		}
	}

	sig := base64.StdEncoding.EncodeToString(signed.RSA.Signature)
	glog.V(2).Infof("Test Signature: %s", sig)

	return nil

}
