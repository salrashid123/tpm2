package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

const defaultRSAExponent = 1<<16 + 1

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	mode   = flag.String("mode", "", "createKey,makeCredential,activateCredential")
	secret = flag.String("secret", "meet me at...", "secret")
	// keyName           = flag.String("keyName", "", "KeyName")
	ekPubFilepub      = flag.String("ekPubFile", "ek.bin", "ekPub file")
	akPubFile         = flag.String("akPubFile", "akPub.bin", "akPub file")
	tpmPath           = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcr               = flag.Int("pcr", -1, "PCR to seal data to. Must be within [0, 23].")
	defaultEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {
	flag.Parse()

	if *pcr < 0 || *pcr > 23 {
		fmt.Fprintf(os.Stderr, "Invalid flag 'pcr': value %d is out of range", *pcr)
		os.Exit(1)
	}

	if *mode != "createKey" && *mode != "makeCredential" && *mode != "activateCredential" {
		fmt.Fprintf(os.Stderr, "mode must be one of createKey|makeCredential|activateCredential got: %v", *mode)
		os.Exit(1)
	}

	var err error
	switch *mode {
	case "createKey":
		name, err := createKeys(*pcr, *tpmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error createKeys: %v\n", err)
			os.Exit(1)
		}
		keyNameBytes, err := hex.DecodeString(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding key: %v\n", err)
			os.Exit(1)
		}
		glog.V(2).Infof("keyNameBytes  %v ", hex.EncodeToString(keyNameBytes))
	case "makeCredential":
		err = makeCredential(*pcr, *tpmPath, *secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error makeCredential: %v\n", err)
			os.Exit(1)
		}
	case "activateCredential":
		err = activateCredential(*pcr, *tpmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error makeCredential: %v\n", err)
			os.Exit(1)
		}
	}

}

func createKeys(pcr int, tpmPath string) (n string, retErr error) {

	glog.V(2).Infof("======= Init CreateKeys ========")

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
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

	pcrList := []int{pcr}
	pcrval, err := tpm2.ReadPCR(rwc, pcr, tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to  ReadPCR : %v", err)
	}
	glog.V(2).Infof("PCR %v Value %v ", pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(2).Infof("======= createPrimary ========")

	ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
	//ekh, _, _, creationHash, _, _, err := tpm2.CreatePrimaryEx(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
	if err != nil {
		glog.Fatalf("creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	// reread the pub eventhough tpm2.CreatePrimary* gives pub
	tpmEkPub, name, _, err := tpm2.ReadPublic(rwc, ekh)
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
	glog.V(2).Infof("ekPub Name: %v", hex.EncodeToString(name))
	glog.V(2).Infof("ekPub: \n%v", string(ekPubPEM))

	glog.V(2).Infof("======= Write (ekPub) ========")
	ekPubBytes, err := tpmEkPub.Encode()
	if err != nil {
		glog.Fatalf("Save failed for ekPubWire: %v", err)
	}
	err = ioutil.WriteFile("ekPub.bin", ekPubBytes, 0644)
	if err != nil {
		glog.Fatalf("Save failed for ekPub: %v", err)
	}

	glog.V(2).Infof("======= CreateKeyUsingAuth ========")

	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Fatalf("Unable to create PolicySecret: %v", err)
	}

	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, defaultKeyParams)
	if err != nil {
		glog.Fatalf("CreateKey failed: %s", err)
	}
	glog.V(5).Infof("akPub: %v,", hex.EncodeToString(akPub))
	glog.V(5).Infof("akPriv: %v,", hex.EncodeToString(akPriv))

	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		glog.Fatalf("Unable to  DecodeCreationData : %v", err)
	}

	glog.V(10).Infof("CredentialData.ParentName.Digest.Value %v", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(10).Infof("CredentialTicket %v", hex.EncodeToString(creationTicket.Digest))
	glog.V(10).Infof("CredentialHash %v", hex.EncodeToString(creationHash))

	glog.V(2).Infof("======= ContextSave (ek) ========")
	ekhBytes, err := tpm2.ContextSave(rwc, ekh)
	if err != nil {
		glog.Fatalf("ContextSave failed for ekh: %v", err)
	}
	err = ioutil.WriteFile("ek.bin", ekhBytes, 0644)
	if err != nil {
		glog.Fatalf("ContextSave failed for ekh: %v", err)
	}
	tpm2.FlushContext(rwc, ekh)

	glog.V(2).Infof("======= ContextLoad (ek) ========")
	ekhBytes, err = ioutil.ReadFile("ek.bin")
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err = tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}

	glog.V(2).Infof("======= LoadUsingAuth ========")

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Fatalf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		log.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(2).Infof("ak keyName %v", kn)

	glog.V(2).Infof("======= Write (akPub) ========")
	err = ioutil.WriteFile("akPub.bin", akPub, 0644)
	if err != nil {
		glog.Fatalf("Save failed for akPub: %v", err)
	}
	glog.V(2).Infof("======= Write (akPriv) ========")
	err = ioutil.WriteFile("akPriv.bin", akPriv, 0644)
	if err != nil {
		glog.Fatalf("Save failed for akPriv: %v", err)
	}
	return kn, nil
}

func makeCredential(pcr int, tpmPath string, sec string) (retErr error) {
	glog.V(2).Infof("======= init MakeCredential ========")

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
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

	glog.V(2).Infof("======= Load (ekPub.bin) ========")
	ekhBytes, err := ioutil.ReadFile("ekPub.bin")
	if err != nil {
		glog.Fatalf("Read failed for ekPub.bin: %v", err)
	}
	ePub, err := tpm2.DecodePublic(ekhBytes)
	if err != nil {
		glog.Fatalf("Error DecodePublic AK %v", ePub)
	}

	ekh, keyName, err := tpm2.LoadExternal(rwc, ePub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		glog.Fatalf("Error loadingExternal EK %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(2).Infof("======= Read (akPub) ========")
	akPub, err := ioutil.ReadFile("akPub.bin")
	if err != nil {
		glog.Fatalf("Read failed for akPub: %v", err)
	}
	tPub, err := tpm2.DecodePublic(akPub)
	if err != nil {
		glog.Fatalf("Error DecodePublic AK %v", tPub)
	}

	h, keyName, err := tpm2.LoadExternal(rwc, tPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		glog.Fatalf("Error loadingExternal AK %v", err)
	}
	defer tpm2.FlushContext(rwc, h)
	glog.V(2).Infof(" Loaded KeyName %v", hex.EncodeToString(keyName))

	glog.V(2).Infof("======= MakeCredential ========")
	credential := []byte(sec)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, credential, keyName)
	if err != nil {
		log.Fatalf("MakeCredential failed: %v", err)
	}
	glog.V(5).Infof("credBlob %v", hex.EncodeToString(credBlob))
	glog.V(5).Infof("encryptedSecret0 %v", hex.EncodeToString(encryptedSecret0))

	glog.V(2).Infof("======= Write (credBlob) ========")
	err = ioutil.WriteFile("credBlob.bin", credBlob, 0644)
	if err != nil {
		glog.Fatalf("Write credBlob failed: %v", err)
	}

	glog.V(2).Infof("======= Write (encryptedSecret0) ========")
	err = ioutil.WriteFile("encryptedSecret0.bin", encryptedSecret0, 0644)
	if err != nil {
		glog.Fatalf("Write encryptedSecret0 failed: %v", err)
	}

	return
}

func activateCredential(pcr int, tpmPath string) (retErr error) {
	glog.V(2).Infof("======= init ActivateCredential ========")

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
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

	glog.V(2).Infof("======= ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile("ek.bin")
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}

	glog.V(2).Infof("======= Read (akPub) ========")
	akPub, err := ioutil.ReadFile("akPub.bin")
	if err != nil {
		glog.Fatalf("Read failed for akPub: %v", err)
	}
	glog.V(2).Infof("======= Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile("akPriv.bin")
	if err != nil {
		glog.Fatalf("Read failed for akPriv: %v", err)
	}

	glog.V(2).Infof("======= Read (credBlob) ========")
	credBlob, err := ioutil.ReadFile("credBlob.bin")
	if err != nil {
		glog.Fatalf("Read failed for credBlob: %v", err)
	}
	glog.V(2).Infof("======= Read (encryptedSecret0) ========")
	encryptedSecret0, err := ioutil.ReadFile("encryptedSecret0.bin")
	if err != nil {
		glog.Fatalf("Read failed for encryptedSecret0: %v", err)
	}

	glog.V(2).Infof("======= LoadUsingAuth ========")

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Fatalf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		log.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	glog.V(2).Infof("keyName %v", hex.EncodeToString(keyName))

	glog.V(2).Infof("======= ActivateCredentialUsingAuth ========")

	sessActivateCredentialSessHandle1, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle1)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle1, nil, nil, nil, 0); err != nil {
		glog.Fatalf("Unable to create PolicySecret: %v", err)
	}

	authCommandActivate1 := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}

	sessActivateCredentialSessHandle2, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle2)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle2, nil, nil, nil, 0); err != nil {
		glog.Fatalf("Unable to create PolicySecret: %v", err)
	}

	authCommandActivate2 := tpm2.AuthCommand{Session: sessActivateCredentialSessHandle2, Attributes: tpm2.AttrContinueSession}

	tl := []tpm2.AuthCommand{authCommandActivate1, authCommandActivate2}

	recoveredCredential1, err := tpm2.ActivateCredentialUsingAuth(rwc, tl, keyHandle, ekh, credBlob, encryptedSecret0)
	if err != nil {
		glog.Fatalf("ActivateCredential failed: %v", err)
	}
	glog.V(2).Infof("recoveredCredential1 %v", string(recoveredCredential1))
	return
}
