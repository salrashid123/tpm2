package main

import (
	"flag"
	"strconv"
	"strings"

	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"

	"github.com/golang/protobuf/proto"

	//"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"

	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
)

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	mode           = flag.String("mode", "", "seal,unseal")
	tpmPath        = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	ekPubFile      = flag.String("ekPubFile", "", "ekPub file in PEM format")
	sealedDataFile = flag.String("sealedDataFile", "", "sealedDataFile file")
	secret         = flag.String("secret", "meet me at...", "secret")
	pcrsValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 23=foo,20=bar.")
	pcrMap         = map[uint32][]byte{}
	flush          = flag.String("flush", "all", "Flush contexts, must be oneof transient|saved|loaded|all")
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
					glog.Fatalf("Error decoding hex string: %v\n", err)
				}
				pcrMap[uint32(u)] = hv

				//rr := hex.Dump(hv)
				glog.V(10).Infof("PCR key: %v\n", uint32(u))
				//glog.V(10).Infof("PCR Values: %v\n", rr)

			}
			//glog.V(10).Infof("PCR Values: %v\n", pcrMap)
		}

		pubPEMData, err := ioutil.ReadFile(*ekPubFile)
		if err != nil {
			glog.Fatalf("Unable to read ekpub: %v", err)
		}
		block, _ := pem.Decode(pubPEMData)
		pub, _ := x509.ParsePKIXPublicKey(block.Bytes)

		mySecret := []byte(*secret)
		var pcrs *pb.PCRs
		if len(pcrMap) == 0 {
			pcrs = nil
		} else {
			pcrs = &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}
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

		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				glog.Fatalf("\ncan't close TPM %q: %v", tpmPath, err)
			}
		}()

		totalHandles := 0
		for _, handleType := range handleNames[*flush] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				glog.Fatalf("getting handles: %v", err)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					glog.Fatalf("flushing handle 0x%x: %v", handle, err)
				}
				glog.V(2).Infof("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}

		ek, err := client.EndorsementKeyRSA(rwc)
		if err != nil {
			glog.Fatalf("Unable to load EK from TPM: %v", err)
		}

		blob := &pb.ImportBlob{}
		dat, err := ioutil.ReadFile(*sealedDataFile)
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
