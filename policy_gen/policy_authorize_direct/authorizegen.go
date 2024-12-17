package main

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	pcr = 23
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
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

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	bitSize := 2048

	// Generate a signing RSA key.
	// this key is used to sign and authorize policies
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	// Extract public component.
	pub := key.Public()

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	log.Printf("Public \n%s\n", pubPEM)
	log.Printf("Private \n%s\n", keyPEM)

	// now load only the public key into the tpm
	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Decrypt:             true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Exponent: uint32(key.PublicKey.E),
				KeyBits:  2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: key.PublicKey.N.Bytes(),
			},
		),
	}

	l, err := tpm2.LoadExternal{
		InPublic:  tpm2.New2B(rsaTemplate),
		Hierarchy: tpm2.TPMRHOwner,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load key: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: l.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	log.Printf("loaded external %s\n", hex.EncodeToString(l.Name.Buffer))

	// now create a policy session for the authorized key
	//  we will need its digest to create they actual AES key
	log.Printf("======= create a policy session for authorized key ========")

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1()

	log.Printf("======= create PolicyAuthorize ========")

	policyRefString := "foooooo"

	pa := &tpm2.PolicyAuthorize{
		PolicySession: sess.Handle(),
		KeySign:       l.Name,
		PolicyRef: tpm2.TPM2BDigest{
			Buffer: []byte(policyRefString),
		},
		CheckTicket: tpm2.TPMTTKVerified{
			Tag:       tpm2.TPMSTVerified,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	_, err = pa.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyAuthorize: %v", err)
	}

	policyAuthorizeDigest, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	cleanup1()

	// now create a create a  pcr policy; we will later sign this

	log.Printf("======= create PolicyPCR ========")
	sesspcr, cleanup1pcr, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1pcr(); err != nil {
			log.Fatalf("cleaning up trial session: %v", err)
		}
	}()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
			},
		},
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sesspcr.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	// get the pcr digest
	pcrPolicyDigest, err := tpm2.PolicyGetDigest{
		PolicySession: sesspcr.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	// 23.16 TPM2_PolicyAuthorize https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	//  aHash ≔ HaHashAlg(approvedPolicy || policyRef)

	policyRef := []byte(policyRefString)
	toDigest := append(pcrPolicyDigest.PolicyDigest.Buffer, policyRef...)

	msgHash := sha256.New()
	_, err = msgHash.Write(toDigest)
	if err != nil {
		log.Fatalf("error getting hash %v\n", err)
	}
	msgHashpcrSum := msgHash.Sum(nil)

	sigpolicy, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, msgHashpcrSum)
	if err != nil {
		log.Fatalf("error executing sign: %v", err)
	}
	log.Printf("ApprovedPolicy+policyRef signature %s\n", hex.EncodeToString(sigpolicy))

	// now create the TPM2B_PUBLIC segment from the tepmplate
	rsa_TPMTPublic_bytes := tpm2.Marshal(rsaTemplate)
	rsa_TPM2BPublic := tpm2.BytesAs2B[tpm2.TPM2BPublic](rsa_TPMTPublic_bytes)
	rsa_TPM2BPublic_bytes := tpm2.Marshal(rsa_TPM2BPublic)
	log.Printf("TPM2B_PUBLIC keySignSegment %s", hex.EncodeToString(rsa_TPM2BPublic_bytes))

	policyRefDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		Buffer: []byte(policyRefString),
	})
	log.Printf("policyRefSegment %s", hex.EncodeToString(policyRefDigestSegment))

	// get the signature
	sig := &tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSASSA,
		Signature: tpm2.NewTPMUSignature(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSignatureRSA{
				Hash: tpm2.TPMAlgSHA256,
				Sig: tpm2.TPM2BPublicKeyRSA{
					Buffer: sigpolicy,
				},
			},
		),
	}
	sig_bytes := tpm2.Marshal(sig)
	log.Printf("signatureSegment %s", hex.EncodeToString(sig_bytes))

	policyCommand := append(rsa_TPM2BPublic_bytes, policyRefDigestSegment...)
	policyCommand = append(policyCommand, sig_bytes...)
	log.Printf("Full PolicyCommand: %s\n", hex.EncodeToString(policyCommand))

	/// ****************************

	log.Printf("======= createPrimary ========")

	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	// now create a key

	// now create the key template and specify the policydigest
	aesTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			Decrypt:             true,
			SignEncrypt:         true,
		},
		AuthPolicy: policyAuthorizeDigest.PolicyDigest, // note the aes key has an auth policy for PolicyAuthorize, not the PCRPolicy
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
				},
			},
		),
	}

	// create the key
	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(aesTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM  %v", err)
	}

	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// now use the key to encrypt
	data := []byte("foooo")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalf("can't read rand %v", err)
	}

	// start a session to create a pcr policy and then a policyauthorize
	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyPCR: %v", err)
	}

	// get the pcr digest
	pcrPolicyDigest2, err := tpm2.PolicyGetDigest{
		PolicySession: sesspcr.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	// *************************************

	// *******************************************************************************

	// now regenerate the policy using just the policyCommand bytes

	// *******************************************************************************

	keyLengthBytes := policyCommand[:2]
	tp, err := tpm2.Unmarshal[tpm2.TPM2BPublic](policyCommand[:2+binary.BigEndian.Uint16(keyLengthBytes)])
	if err != nil {
		log.Fatalf("can't getting TPM2BPublic: %v", err)
	}
	reGenKeyPublic, err := tp.Contents()
	if err != nil {
		log.Fatalf("error getting  TPMTPublic: %v", err)
	}

	flush := tpm2.FlushContext{
		FlushHandle: l.ObjectHandle,
	}
	_, err = flush.Execute(rwr)

	l2, err := tpm2.LoadExternal{
		InPublic:  tpm2.New2B(*reGenKeyPublic),
		Hierarchy: tpm2.TPMRHOwner,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load key: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: l2.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	remainder := policyCommand[2+binary.BigEndian.Uint16(keyLengthBytes):]
	//extract policyRefDigestSegment
	lenpolicyRefDigestSegment := remainder[:2]
	dda, err := tpm2.Unmarshal[tpm2.TPM2BDigest](remainder[:2+binary.BigEndian.Uint16(lenpolicyRefDigestSegment)])
	if err != nil {
		log.Fatalf("can't load policyRefDigestSegment: %v", err)
	}

	toDigest2 := append(pcrPolicyDigest2.PolicyDigest.Buffer, dda.Buffer...)
	msgHash2 := sha256.New()
	_, err = msgHash2.Write(toDigest2)
	if err != nil {
		log.Fatalf("error getting hash %v\n", err)
	}
	msgHashpcrSum2 := msgHash2.Sum(nil)

	//extract TPMTSignature

	regenSig := remainder[2+binary.BigEndian.Uint16(lenpolicyRefDigestSegment):]

	tts, err := tpm2.Unmarshal[tpm2.TPMTSignature](regenSig)
	if err != nil {
		log.Fatalf("can't load TPMTSignature: %v", err)
	}

	// now ready

	v, err := tpm2.VerifySignature{
		KeyHandle: l2.ObjectHandle,
		Digest: tpm2.TPM2BDigest{
			Buffer: msgHashpcrSum2,
		},
		Signature: *tts,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing VerifySignature: %v", err)
	}

	// v, err := tpm2.VerifySignature{
	// 	KeyHandle: l2.ObjectHandle,
	// 	Digest: tpm2.TPM2BDigest{
	// 		Buffer: msgHashpcrSum,
	// 	},
	// 	Signature: tpm2.TPMTSignature{
	// 		SigAlg: tpm2.TPMAlgRSASSA,
	// 		Signature: tpm2.NewTPMUSignature(
	// 			tpm2.TPMAlgRSASSA,
	// 			&tpm2.TPMSSignatureRSA{
	// 				Hash: tpm2.TPMAlgSHA256,
	// 				Sig: tpm2.TPM2BPublicKeyRSA{
	// 					Buffer: sigpolicy,
	// 				},
	// 			},
	// 		),
	// 	},
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing VerifySignature: %v", err)
	// }

	//***********************

	_, err = tpm2.PolicyAuthorize{
		PolicySession:  sess2.Handle(),
		ApprovedPolicy: pcrPolicyDigest2.PolicyDigest, // use the expected digest we want to sign
		KeySign:        l2.Name,
		PolicyRef:      *dda,
		CheckTicket:    v.Validation,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyAuthorize: %v", err)
	}

	// now use the initialized policy to encrypt/decrypt
	keyAuth2 := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   sess2,
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth2, iv, data, false)

	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	log.Printf("IV: %s", hex.EncodeToString(iv))
	log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

}

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCFB,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}

func getExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}
