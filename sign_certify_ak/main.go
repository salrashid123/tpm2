package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"log"

	//"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"

	"crypto"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

const ()

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L48

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
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	unrestrictedKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
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
	log.Println("======= Init  ========")
	pcr := 23

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
		if err != nil {
			log.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				log.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			log.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	log.Printf("%d handles flushed\n", totalHandles)

	// Acquire and use PCR23's value to use in auth'd sessions
	pcrList := []int{23}
	pcrval, err := tpm2.ReadPCR(rwc, pcr, tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to  ReadPCR : %v", err)
	}
	log.Printf("PCR %v Value %v ", pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	//pcrSelection23 = tpm2.PCRSelection{}
	emptyPassword := ""

	// Create EK

	log.Printf("======= createPrimary (EK) ========")

	ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)
	log.Printf("======= CreateKeyUsingAuth ========")

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
		log.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		log.Fatalf("Unable to create PolicySecret: %v", err)
	}

	// Create AK

	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPriv, akPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, defaultKeyParams)
	if err != nil {
		log.Fatalf("Create AKKey failed: %s", err)
	}
	log.Printf("akPub: %v,", hex.EncodeToString(akPub))
	log.Printf("akPriv: %v,", hex.EncodeToString(akPriv))

	tPub, err := tpm2.DecodePublic(akPub)
	if err != nil {
		log.Fatalf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		log.Fatalf("akPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		log.Fatalf("Unable to convert akPub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)

	log.Printf("akPub PEM \n%s", string(akPubPEM))

	// Load the AK into context

	sessLoadHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessLoadHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
		log.Fatalf("Unable to create PolicySecret: %v", err)
	}
	authCommandLoad := tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

	aKkeyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	defer tpm2.FlushContext(rwc, aKkeyHandle)
	if err != nil {
		log.Fatalf("Load AK failed: %s", err)
	}
	log.Printf("AK keyName: %v,", hex.EncodeToString(keyName))

	tpm2.FlushContext(rwc, sessLoadHandle)
	tpm2.FlushContext(rwc, sessCreateHandle)

	// Create Child of AK that is Unrestricted (does not have tpm2.FlagRestricted)
	// Under endorsement handle
	log.Printf("======= CreateKeyUsingAuthUnrestricted ========")

	sessCreateHandle, _, err = tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	// if err = tpm2.PolicyPCR(rwc, sessCreateHandle, nil, pcrSelection23); err != nil {
	// 	log.Fatalf("PolicyPCR failed: %v", err)
	// }

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		log.Fatalf("Unable to create PolicySecret: %v", err)
	}
	authCommandCreateAuth = tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}
	//nullCommandCreate := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}

	// what i'd really want is a child key of aKkeyHandle but there's some policy i'm isssing
	// error code 0x1d : a policy check failed exit status 1
	// ukPriv, ukPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, aKkeyHandle, pcrSelection23, authCommandCreateAuth, emptyPassword, unrestrictedKeyParams)

	ukPriv, ukPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, unrestrictedKeyParams)

	if err != nil {
		log.Fatalf("UnrestrictedCreateKey failed: %s", err)
	}
	log.Printf("Unrestricted ukPub: %v,", hex.EncodeToString(ukPub))
	log.Printf("Unrestricted ukPriv: %v,", hex.EncodeToString(ukPriv))

	tpm2.FlushContext(rwc, sessCreateHandle)

	// Load the unrestricted key
	sessLoadHandle, _, err = tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessLoadHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
		log.Fatalf("Unable to create PolicySecret: %v", err)
	}
	authCommandLoad = tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

	ukeyHandle, ukeyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, ukPub, ukPriv)

	if err != nil {
		log.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, ukeyHandle)
	log.Printf("ukeyName: %v,", hex.EncodeToString(ukeyName))

	// Certify the Unrestricted key using the AK
	attestation, csig, err := tpm2.Certify(rwc, emptyPassword, emptyPassword, ukeyHandle, aKkeyHandle, nil)
	if err != nil {
		log.Fatalf("Load failed: %s", err)
	}
	log.Printf("Certify Attestation: %v,", hex.EncodeToString(attestation))
	log.Printf("Certify Signature: %v,", hex.EncodeToString(csig))
	tpm2.FlushContext(rwc, sessLoadHandle)

	// Now Sign some arbitrary data with the unrestricted Key
	dataToSign := []byte("secret")
	digest, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSign)
	if err != nil {
		log.Fatalf("Error Generating Hash: %v", err)
	}

	sig, err := tpm2.Sign(rwc, ukeyHandle, "", digest[:], &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		log.Fatalf("Error Signing: %v", err)
	}
	log.Printf("Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

	// Verify the Certification value:
	log.Printf("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		log.Fatalf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}
	log.Printf("     Attestation att.AttestedCertifyInfo.QualifiedName: %s", hex.EncodeToString(att.AttestedCertifyInfo.QualifiedName.Digest.Value))

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: csig,
	}

	// Verify signature of Attestation by using the PEM Public key for AK
	log.Printf("     Decoding PublicKey for AK ========")

	block, _ := pem.Decode(akPubPEM)
	if block == nil {
		log.Fatalf("Unable to decode akPubPEM %v", err)
	}

	r, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Unable to create rsa Key from PEM %v", err)
	}
	rsaPub := *r.(*rsa.PublicKey)

	// p, err := tpm2.DecodePublic(akPub)
	// if err != nil {
	// 	log.Fatalf("DecodePublic failed: %v", err)
	// }
	// rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	// rsaPub = *ap.(*rsa.PublicKey)

	hsh := crypto.SHA256.New()
	hsh.Write(attestation)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		log.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
	log.Printf("Attestation Verified")

}
