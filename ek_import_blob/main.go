package main

import (
	"flag"

	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	pb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

/*
go run main.go  --mode=seal --secret "hello world" --ekPubFile=ek.pem --sealedDataFile=sealed.dat --logtostderr=1 -v 5
sudo ./main --mode=unseal --sealedDataFile=sealed.dat --logtostderr=1 -v 5
*/

var (
	mode           = flag.String("mode", "", "seal,unseal")
	ekPubFile      = flag.String("ekPubFile", "", "ekPub file in PEM format")
	sealedDataFile = flag.String("sealedDataFile", "", "sealedDataFile file")
	secret         = flag.String("secret", "meet me at...", "secret")
)

func main() {
	flag.Parse()

	switch *mode {
	case "seal":
		if *ekPubFile == "" || *sealedDataFile == "" {
			glog.Fatalf("ekPubFile and sealedDataFile must be specified for sealing")
		}
		pubPEMData, err := ioutil.ReadFile(*ekPubFile)
		if err != nil {
			glog.Fatalf("Unable to read ekpub: %v", err)
		}
		block, _ := pem.Decode(pubPEMData)
		pub, _ := x509.ParsePKIXPublicKey(block.Bytes)

		mySecret := []byte(*secret)
		blob, err := server.CreateImportBlob(pub, mySecret)
		if err != nil {
			glog.Fatalf("Unable to CreateImportBlob : %v", err)
		}
		data, err := proto.Marshal(blob)
		if err != nil {
			glog.Fatalf("marshaling error: ", err)
		}
		err = ioutil.WriteFile(*sealedDataFile, data, 0644)
		if err != nil {
			glog.Fatalf("Unable to write file: %v", err)
		}
		glog.Infof("Sealed data to file.. %v", *sealedDataFile)

	case "unseal":
		if *sealedDataFile == "" {
			glog.Fatalf("sealedDataFile must be specified for sealing")
		}
		rwc, err := tpm2.OpenTPM("/dev/tpm0")
		if err != nil {
			glog.Fatalf("Unable to openTPM: %v", err)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				glog.Fatalf("can't close TPM %v", err)
			}
		}()
		ek, err := tpm2tools.EndorsementKeyRSA(rwc)
		if err != nil {
			glog.Fatalf("Unable to load EK from TPM: %v", err)
		}

		blob := &pb.ImportBlob{}
		dat, err := ioutil.ReadFile("sealed.dat")
		if err != nil {
			glog.Fatalf("error reading sealed.dat: ", err)
		}
		err = proto.Unmarshal(dat, blob)
		if err != nil {
			glog.Fatal("unmarshaling error: ", err)
		}
		myDecodedSecret, err := ek.Import(rwc, blob)
		glog.Infof("Unsealed secret: %v", string(myDecodedSecret))
		if err != nil {
			glog.Fatalf("Unable to Import sealed data: %v", err)
		}
	}
}
