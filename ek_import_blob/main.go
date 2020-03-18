package main

import (
	"flag"
	"strconv"
	"strings"

	"crypto/x509"
	"encoding/hex"
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
	pcrsValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 23:=foo,20=bar.")
	pcrMap         = map[uint32][]byte{}
)

func main() {
	flag.Parse()

	switch *mode {
	case "seal":
		if *ekPubFile == "" || *sealedDataFile == "" {
			glog.Fatalf("ekPubFile and sealedDataFile must be specified for sealing")
		}

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

		pubPEMData, err := ioutil.ReadFile(*ekPubFile)
		if err != nil {
			glog.Fatalf("Unable to read ekpub: %v", err)
		}
		block, _ := pem.Decode(pubPEMData)
		pub, _ := x509.ParsePKIXPublicKey(block.Bytes)

		mySecret := []byte(*secret)
		var pcrs *pb.Pcrs
		if len(pcrMap) == 0 {
			pcrs = nil
		} else {
			pcrs = &pb.Pcrs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}
		}
		blob, err := server.CreateImportBlob(pub, mySecret, pcrs)
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
		myDecodedSecret, err := ek.Import(blob)
		glog.Infof("Unsealed secret: %v", string(myDecodedSecret))
		if err != nil {
			glog.Fatalf("Unable to Import sealed data: %v", err)
		}
	}
}
