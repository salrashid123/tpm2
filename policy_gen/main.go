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

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
//     sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
//     sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

// export TPM2TOOLS_TCTI="swtpm:port=2321"
// tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
// $ tpm2_pcrread sha256:23
//   sha256:
//     23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

const (
	pcr = 23
)

const (
	keyPassword = "keypwd"
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

	// Generate RSA key.
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

	log.Printf("Public %s\n", pubPEM)
	log.Printf("Private %s\n", keyPEM)

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

	// first create primary
	log.Printf("======= createPrimary ========")

	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
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
	log.Printf("======= create ========")

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			log.Fatalf("cleaning up trial session: %v", err)
		}
	}()

	// manually generate the structs for a PCR policy;  we'll use these later to
	// just print out the command sequences

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
			},
		},
	}

	expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
	if err != nil {
		log.Printf("ERROR:  could not get PolicySession: %v", err)
		return
	}

	// now marshal each part and then concat them; thats the actual raw command thats run

	// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	pcrSelectionSegment := tpm2.Marshal(sel)
	pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		Buffer: expectedDigest,
	})

	commandParameter := append(pcrDigestSegment, pcrSelectionSegment...)
	// 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
	log.Printf("pcrSelectionSegment %s", hex.EncodeToString(pcrSelectionSegment))
	log.Printf("pcrDigestSegment %s", hex.EncodeToString(pcrDigestSegment))

	log.Printf("commandParameter %s", hex.EncodeToString(commandParameter))

	// create a key with a pcr and policyauthvalue
	policyRefString := "foobar"
	_, err = tpm2.PolicySecret{
		PolicySession: sess.Handle(),
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sess.NonceTPM(),
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: []byte(policyRefString),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	expirationTime := 10

	_, err = tpm2.PolicySigned{
		PolicySession: sess.Handle(),
		AuthObject:    l.ObjectHandle,
		NonceTPM:      sess.NonceTPM(),
		// Expiration:    expirationTime,
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: []byte(policyRefString),
		},
		Auth: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig: tpm2.TPM2BPublicKeyRSA{
						Buffer: pub.(*rsa.PublicKey).N.Bytes(),
					},
				},
			),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policysigned: %v", err)
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	// ******** PolicyPCR Bytes
	// the cpbytes should be the same commandParameter as above

	// now to test, generate the pcr policy but this time
	// inject the cpbytes as the command directly
	tp := tpm2.PolicyPCR{}

	// inject the parameters into the struct
	err = tpm2.ReqParameters(commandParameter, &tp)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}

	// do the same 'bytes' to struct conversion for policyauthvalue
	ta := tpm2.PolicyAuthValue{}

	// this doens't have a command body so specify nil
	err = tpm2.ReqParameters(nil, &ta)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}

	/// ****************************

	// ******** PolicySecret Bytes

	a := make([]byte, 4)
	hintHandle := tpm2.TPMRHEndorsement.HandleValue()
	//hintHandle = 0
	binary.BigEndian.PutUint32(a, hintHandle) // TPMRHEndorsement TPMHandle = 0x4000000B
	log.Printf("PolicySecret objectHandleHint hex %s\n", hex.EncodeToString(a))

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(tpm2.TPMRHEndorsement.KnownName().Buffer)))
	var m []byte
	m = append(m, b...)
	m = append(m, tpm2.TPMRHEndorsement.KnownName().Buffer...)
	log.Printf("PolicySecret Name %s\n", hex.EncodeToString(m)) // pg 79 Names https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf

	log.Printf("PolicySecret PolicyRef %s\n", hex.EncodeToString([]byte(policyRefString)))

	var policySecretBytes []byte
	policySecretBytes = append(policySecretBytes, a...)
	policySecretBytes = append(policySecretBytes, m...)
	policySecretBytes = append(policySecretBytes, []byte(policyRefString)...)
	log.Printf("PolicySecret CPBytes %s", hex.EncodeToString(policySecretBytes))

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
		AuthPolicy: pgd.PolicyDigest,
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
					Buffer: []byte(keyPassword),
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

	// start a session
	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(keyPassword))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	// ************** recreate policysecret

	var na tpm2.TPMHandle

	hintBytes := policySecretBytes[:4]
	hintInt32 := binary.BigEndian.Uint32(hintBytes)
	log.Printf("Recreated PolicySecret objectHandleHint %d\n", hintInt32)

	nameLengthBytes := policySecretBytes[4 : 4+2]
	log.Printf("Recreated PolicySecret nameLengthBytes %s\n", hex.EncodeToString(nameLengthBytes))
	nameBytes := policySecretBytes[4+2 : 4+2+binary.BigEndian.Uint16(nameLengthBytes)]
	log.Printf("Recreated PolicySecret nameBytes %s\n", hex.EncodeToString(nameBytes))
	nc, err := tpm2.Unmarshal[tpm2.TPM2BName](append(nameLengthBytes, nameBytes...))
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	nonceBytes := policySecretBytes[4+2+binary.BigEndian.Uint16(nameLengthBytes):]
	log.Printf("Recreated PolicySecret nonceBytes %s\n", hex.EncodeToString(nonceBytes))
	if hintInt32 != 0 {
		if hex.EncodeToString(tpm2.HandleName(tpm2.TPMHandle(hintInt32)).Buffer) != hex.EncodeToString(nc.Buffer) {
			log.Fatalf("names do not match: %v", err)
		}
		na = tpm2.TPMHandle(hintInt32)
	} else {
		na = tpm2.TPMHandle(binary.BigEndian.Uint32(nc.Buffer))
	}
	_, err = tpm2.PolicySecret{
		PolicySession: sess2.Handle(),
		AuthHandle:    na, //tpm2.TPMHandle(hintInt32), // tpm2.TPMRHEndorsement,
		NonceTPM:      sess2.NonceTPM(),
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: nonceBytes,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	// TPM2.0 spec, Revision 1.38, Part 3 nonce must be present if expiration is non-zero.
	// aHash ≔ HauthAlg(nonceTPM || expiration || cpHashA || policyRef)
	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, uint32(expirationTime))
	toDigest := append(sess2.NonceTPM().Buffer, expBytes...)
	cpHash := []byte{}
	toDigest = append(toDigest, cpHash...)
	policyRef := []byte(policyRefString)
	toDigest = append(toDigest, policyRef...)

	msgHash := sha256.New()
	_, err = msgHash.Write(toDigest)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, msgHashSum)
	if err != nil {
		log.Fatalf("error executing sign: %v", err)
	}
	log.Printf("Sig %s\n", hex.EncodeToString(sig))

	_, err = tpm2.PolicySigned{
		PolicySession: sess2.Handle(),
		AuthObject:    l.ObjectHandle,
		NonceTPM:      sess2.NonceTPM(),
		Expiration:    int32(expirationTime),
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: []byte(policyRefString),
		},
		Auth: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig: tpm2.TPM2BPublicKeyRSA{
						Buffer: sig,
					},
				},
			),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policysigned: %v", err)
	}

	// use the raw command bytes to generate the pcr policy
	tp2 := tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
	}
	err = tpm2.ReqParameters(commandParameter, &tp2)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}
	_, err = tp2.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing ReqParameters: %v", err)
	}

	// and the authvalue
	ta2 := tpm2.PolicyAuthValue{
		PolicySession: sess2.Handle(),
	}

	err = tpm2.ReqParameters(nil, &ta2)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}
	_, err = ta2.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing ReqParameters: %v", err)
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
