package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
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
	tpmPath  = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcr      = flag.Int("pcr", 0, "PCR to seal data to. Must be within [0, 23].")
	pcrValue = flag.String("pcrValue", "0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea", "PCR value. on GCP Shielded VM, debian10 with secureboot: 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea is for PCR 0")
)

func main() {
	flag.Parse()

	if *pcr < 0 || *pcr > 23 {
		fmt.Fprintf(os.Stderr, "Invalid flag 'pcr': value %d is out of range", *pcr)
		os.Exit(1)
	}

	var err error

	glog.V(2).Infof("======= Init CreateKeys ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
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

	glog.V(2).Infof("%d handles flushed\n", totalHandles)

	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to  ReadPCR : %v", err)
	}
	glog.V(2).Infof("PCR Value %v ", pcr, hex.EncodeToString(pcrval))

	var idx tpmutil.Handle = 0x1500000
	var data = []byte("testdata")
	glog.V(2).Infof("Data to save to NV  %s ", pcr, hex.EncodeToString(data))
	var attr = tpm2.AttrOwnerRead | tpm2.AttrOwnerWrite | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear

	emptyPassword := ""
	if err := tpm2.NVUndefineSpace(rwc, emptyPassword, tpm2.HandleOwner, idx); err != nil {
		glog.V(10).Infof("Unable to  NVUndefineSpace : %v", err)
	}

	if err := tpm2.NVDefineSpace(rwc,
		tpm2.HandleOwner,
		idx,
		emptyPassword,
		emptyPassword,
		nil,
		attr,
		uint16(len(data)),
	); err != nil {
		glog.Fatalf("Unable to  NVDefineSpace : %v", err)
	}
	defer tpm2.NVUndefineSpace(rwc, emptyPassword, tpm2.HandleOwner, idx)

	if err := tpm2.NVWrite(rwc, tpm2.HandleOwner, idx, emptyPassword, data, 0); err != nil {
		glog.Fatalf("Unable to  NVDefineSpace : %v", err)
	}

	if err := tpm2.NVWriteLock(rwc, tpm2.HandleOwner, idx, emptyPassword); err != nil {
		glog.Fatalf("Unable to  NVWriteLock : %v", err)
	}

	pub, err := tpm2.NVReadPublic(rwc, idx)
	if err != nil {
		glog.Fatalf("Unable to  NVReadPublic : %v", err)
	}
	if int(pub.DataSize) != len(data) {
		glog.Fatalf("length mismatch : %v", err)
	}

	// Read all of the data with NVReadEx and compare to what was written
	outdata, err := tpm2.NVReadEx(rwc, idx, tpm2.HandleOwner, emptyPassword, 0)
	if err != nil {
		glog.Fatalf("Unable to  NVReadEx : %v", err)
	}
	if !bytes.Equal(data, outdata) {
		glog.Fatalf("bytes read unequal : %v", err)
	}
	glog.V(10).Infof("NV Data %s", hex.EncodeToString(outdata))

	// Enable read lock
	if err := tpm2.NVReadLock(rwc, tpm2.HandleOwner, idx, emptyPassword); err != nil {
		glog.Fatalf("Unable to  NVReadLock : %v", err)
	}

	//  *************** get Attestation Key key from NVIndex

	// // Reserved Handles from "TCG TPM v2.0 Provisioning Guidance" - v1r1 - Table 2
	// const (
	// 	EKReservedHandle     = tpmutil.Handle(0x81010001)
	// 	EKECCReservedHandle  = tpmutil.Handle(0x81010002)
	// 	SRKReservedHandle    = tpmutil.Handle(0x81000001)
	// 	SRKECCReservedHandle = tpmutil.Handle(0x81000002)
	// )

	// // NV Indices holding GCE AK Templates
	// const (
	// 	GceAKTemplateNVIndexRSA uint32 = 0x01c10001
	// 	GceAKTemplateNVIndexECC uint32 = 0x01c10003
	// )

	data, err = tpm2.NVReadEx(rwc, tpmutil.Handle(client.GceAKTemplateNVIndexRSA), tpm2.HandleOwner, "", 0)
	if err != nil {
		glog.Fatalf("read error at index %d: %w", client.GceAKTemplateNVIndexRSA, err)
	}
	template, err := tpm2.DecodePublic(data)
	if err != nil {
		glog.Fatalf("index %d data was not a TPM key template: %w", client.GceAKTemplateNVIndexRSA, err)
	}

	akh, _, _, _, _, _, err := tpm2.CreatePrimaryEx(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, emptyPassword, emptyPassword, template)
	if err != nil {
		glog.Fatalf("creating AK: %v", err)
	}
	defer tpm2.FlushContext(rwc, akh)

	// reread the pub eventhough tpm2.CreatePrimary* gives pub
	tpmEkPub, name, _, err := tpm2.ReadPublic(rwc, akh)
	if err != nil {
		glog.Fatalf("ReadPublic failed: %s", err)
	}

	p, err := tpmEkPub.Key()
	if err != nil {
		glog.Fatalf("tpmEkPub.Key() failed: %s", err)
	}
	glog.V(10).Infof("tpmEkPub: \n%v", p)

	b, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		glog.Fatalf("Unable to convert ekpub: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	glog.V(2).Infof("akPub Name: %v", hex.EncodeToString(name))
	glog.V(2).Infof("akPub: \n%v", string(ekPubPEM))

}
