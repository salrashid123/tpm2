package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"strconv"
	"strings"

	"io/ioutil"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	pb "github.com/google/go-tpm-tools/proto"

	"github.com/google/go-tpm-tools/server"
)

const (
	defaultP12Password = "notasecret"
)

var (
	ekPubFile    = flag.String("ekPubFile", "ek.pem", "Path to the ekPubFile PEM).")
	pcrsValues   = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 23:=foo,20=bar.")
	rsaKeyFile   = flag.String("rsaKeyFile", "private_nopass.pem", "Path to RSA  Service account Private PEM file")
	sealedOutput = flag.String("sealedOutput", "sealed.dat", "Filename to save the sealed RSA Private .")
	pcrMap       = map[uint32][]byte{}
)

func main() {
	flag.Parse()

	if *ekPubFile == "" {
		glog.Fatalf("ekPubFile must be set")
	}
	if *rsaKeyFile == "" {
		glog.Fatalf("rsaKeyFile must be set")
	}

	// TODO: improve this, i' making assumptions on the parameters
	if *pcrsValues != "" {
		entries := strings.Split(*pcrsValues, ",")
		pcrMap = make(map[uint32][]byte)
		for _, e := range entries {
			parts := strings.Split(e, "=")
			u, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				glog.Fatalf("Error parsing uint64->32: %v\n", err)
			}

			hv, err := hex.DecodeString(parts[1])
			if err != nil {
				glog.Fatalf("Error parsing uint64->32: %v\n", err)
			}
			pcrMap[uint32(u)] = hv

			rr := hex.Dump(hv)
			glog.V(10).Infof("PCR key: %v\n", uint32(u))
			glog.V(10).Infof("PCR Values: %v\n", rr)

		}
		glog.V(10).Infof("PCR Values: %v\n", pcrMap)
	}

	err := createSigningKeyImportBlob(*ekPubFile, *rsaKeyFile, *sealedOutput)
	if err != nil {
		glog.Fatalf("Error createSigningKeyImportBlob: %v\n", err)
	}

}

func createSigningKeyImportBlob(ekPubFile string, rsaKeyFile string, sealedOutput string) (retErr error) {

	glog.V(2).Infof("======= Init createSigningKeyImportBlob ========")

	glog.V(2).Infof("======= Loading ekPub ========")

	var ekPub crypto.PublicKey

	pubPEMData, err := ioutil.ReadFile(ekPubFile)
	if err != nil {
		glog.Fatalf("Unable to read ekpub: %v", err)
	}
	block, _ := pem.Decode(pubPEMData)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		glog.Fatalf("Unable to decode pub pem: %v", err)
	}

	ekPub = pub.(crypto.PublicKey)

	glog.V(10).Infof("Loaded ekPub %v", ekPub)

	glog.V(2).Infof("======= Loading Service Account RSA Key ========")

	privPemBytes, err := ioutil.ReadFile(rsaKeyFile)
	if err != nil {
		glog.Fatalf("Unable to read rsaKeyFile: %v", err)
	}

	privBlock, _ := pem.Decode(privPemBytes)

	signingKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		glog.Fatalf("Unable to read read rsa PrivateKey: %v", err)
	}

	glog.V(2).Infof("======= Generating Test Signature ========")

	data := []byte("foobar")

	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	signed, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, d)
	if err != nil {
		glog.Fatalf("Unable to sign %v", err)
	}

	sig := base64.StdEncoding.EncodeToString(signed)
	glog.V(2).Info("Signature: %s", sig)

	glog.V(2).Infof("======= CreateSigningKeyImportBlob for RSA Key: ========")
	var pcrs *pb.Pcrs
	if len(pcrMap) == 0 {
		pcrs = nil
	} else {
		pcrs = &pb.Pcrs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}
	}
	blob, err := server.CreateSigningKeyImportBlob(ekPub, signingKey, pcrs)
	if err != nil {
		glog.Fatalf("Unable to CreateSigningKeyImportBlob: %v", err)
	}

	glog.V(2).Infof("======= Saving sealedkey ========")

	data, err = proto.Marshal(blob)
	if err != nil {
		glog.Fatalf("marshaling error: ", err)
	}
	err = ioutil.WriteFile(sealedOutput, data, 0644)
	if err != nil {
		glog.Fatalf("Unable to write file: %v", err)
	}
	glog.Infof("Sealed data to file.. %s", sealedOutput)

	// glog.V(2).Infof("======= Loading sealedkey ========")
	// importblob := &pb.ImportBlob{}
	// importdata, err := ioutil.ReadFile("sealedkey.dat")
	// if err != nil {
	// 	glog.Fatalf("error reading sealed.dat: ", err)
	// }
	// err = proto.Unmarshal(importdata, importblob)
	// if err != nil {
	// 	glog.Fatal("Unmarshal error: ", err)
	// }
	// glog.V(10).Infof("SealedKey %v", importblob)
	return nil
}
