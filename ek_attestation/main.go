package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	secret  = flag.String("secret", "meet me at...", "secret")

	keySensitive = flag.String("keySensitive", "myhamckey", "random hmac key")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	//// ********************  1 ATTESTOR
	log.Println("======= create ekPublic on Attestor  ========")
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	// first get the EKPublic from the Attestor (HOST)

	cCreateEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateEK.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// read from handle
	// cCreateGCEEK, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(EKReservedHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	// }
	log.Printf("Name %s\n", hex.EncodeToString(cCreateEK.Name.Buffer))

	// now extract the PEM format
	rsaEKpub, err := cCreateEK.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rsaEKDetail, err := rsaEKpub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rsaEKUnique, err := rsaEKpub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	primaryRsaEKPub, err := tpm2.RSAPub(rsaEKDetail, rsaEKUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	b4, err := x509.MarshalPKIXPublicKey(primaryRsaEKPub)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b4,
	}
	primaryEKPEMByte := pem.EncodeToMemory(block)

	log.Printf("RSA EK createPrimary public \n%s\n", string(primaryEKPEMByte))

	// flush the original handl
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEK.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	//// ******************** 2  VERIFIER
	// now pretend to send that EK Public PEM to the Verifier

	log.Println("======= send the ekPub.PEM to the Verifier ========")
	// Load the EKPub into and duplicate a random hmac key

	publicKey, _ := pem.Decode(primaryEKPEMByte)

	p, err := x509.ParsePKIXPublicKey(publicKey.Bytes)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	ekrsaPub, ok := p.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Failed to get public")
	}

	// now regenerate the tpm key template from the rsa public key
	u := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: ekrsaPub.N.Bytes(),
		},
	)

	ekPububFromPEMTemplate := tpm2.RSAEKTemplate
	ekPububFromPEMTemplate.Unique = u

	// ************ now duplidate an hmac key
	log.Println("======= create a random HMAC key and duplicate it ========")

	sv := make([]byte, 32)
	io.ReadFull(rand.Reader, sv)
	privHash := crypto.SHA256.New()
	privHash.Write(sv)
	privHash.Write([]byte(*keySensitive))

	dupKeyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						}),
				},
			}),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	sens := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BSensitiveData{Buffer: []byte(*keySensitive)},
		),
	}

	sens.AuthValue = tpm2.TPM2BAuth{
		Buffer: []byte(nil), // set any userAuth
	}

	// the follwoing performs a duplication of the  dupKeyTemplate wihout involving a local TPM

	sens2B := tpm2.Marshal(sens)

	packedSecret := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	var seed, encryptedSeed []byte

	// reacquire the TPM's ek public RSA details
	ek, err := ekPububFromPEMTemplate.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	ekHash, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		log.Fatalf("Failed ek.Scheme.Scheme.Hash: %v", err)
	}

	ekaekBits, err := ek.Symmetric.KeyBits.AES()
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	symSize := int(*ekaekBits)

	//  start createRSASeed
	aeskeybits, err := ek.Symmetric.KeyBits.AES()
	if err != nil {
		log.Fatalf("Failed aeskeybits: %v", err)
	}
	seedSize := *aeskeybits / 8
	seed = make([]byte, seedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		panic(err)
	}

	encryptedSeed, err = rsa.EncryptOAEP(
		ekHash.New(),
		rand.Reader,
		ekrsaPub,
		seed,
		[]byte("DUPLICATE\x00"))
	if err != nil {
		log.Fatalf("Failed EncryptOAEP: %v", err)
	}

	encryptedSeed, err = tpmutil.Pack(encryptedSeed)
	if err != nil {
		log.Fatalf("Failed encryptedSeed: %v", err)
	}

	name, err := tpm2.ObjectName(&dupKeyTemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	nameEncoded := name.Buffer

	fmt.Printf("duplicateTemplate Name %s\n", hex.EncodeToString(nameEncoded))

	symmetricKey := tpm2.KDFa(
		ekHash,
		seed,
		"STORAGE",
		nameEncoded,
		/*contextV=*/ nil,
		symSize)

	aescipher, err := aes.NewCipher(symmetricKey)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	encryptedSecret := make([]byte, len(packedSecret))
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(aescipher, iv).XORKeyStream(encryptedSecret, packedSecret)
	// end encryptSecret

	// start createHMAC

	macKey := tpm2.KDFa(
		ekHash,
		seed,
		"INTEGRITY",
		/*contextU=*/ nil,
		/*contextV=*/ nil,
		ekHash.New().Size()*8)

	mac := hmac.New(func() hash.Hash { return ekHash.New() }, macKey)
	mac.Write(encryptedSecret)
	mac.Write(nameEncoded)
	hmacSum := mac.Sum(nil)
	// end createHMAC

	dup := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: hmacSum})
	dup = append(dup, encryptedSecret...)

	dupTemplateMarshalled := tpm2.Marshal(&dupKeyTemplate)

	// we've now dupliated the hmac key using the EKPub, now the attestor needs to send
	//  dup, dupseed and dupPub to the attestor

	log.Println("======= verifier sends duplicate key, duplicate seed and duplicate pub to Attestor ========")

	// on the attestor, recreate the EK (since this step maybe at a later time than the original step to create the ekPublic pem)
	log.Println("======= Attestor creates  EK ========")
	cPrimaryEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte(nil)),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("CreatePrimary: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimaryEK.ObjectHandle,
		}
		_, _ = flush.Execute(rwr)
	}()

	/// *********

	log.Println("======= Attestor imports the duplicated hmac key ========")

	import_sess, import_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("FailedPolicySession: %v", err)
	}
	defer import_session_cleanup()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: import_sess.Handle(),
		NonceTPM:      import_sess.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed PolicySecret: %v", err)
	}

	// now import the duplicated key
	dupPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](dupTemplateMarshalled)
	if err != nil {
		log.Fatalf("Failed Unmarshal: %v", err)
	}

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimaryEK.ObjectHandle,
			Name:   cPrimaryEK.Name,
			Auth:   import_sess,
		},
		ObjectPublic: tpm2.New2B(*dupPub),
		Duplicate: tpm2.TPM2BPrivate{
			Buffer: dup,
		},
		InSymSeed: tpm2.TPM2BEncryptedSecret{
			Buffer: encryptedSeed,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("FailedImportx: %v", err)
	}
	err = import_session_cleanup()
	if err != nil {
		log.Fatalf("Failed cleanup: %v", err)
	}

	// now load the imported key

	load_sess, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("FailedPolicySession: %v", err)
	}
	defer load_session_cleanup()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: load_sess.Handle(),
		NonceTPM:      load_sess.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed PolicySecret: %v", err)
	}

	loadedHmacKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimaryEK.ObjectHandle,
			Name:   cPrimaryEK.Name,
			Auth:   load_sess,
		},
		InPublic:  tpm2.New2B(dupKeyTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadedHmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Println("======= Attestor creates AK ========")

	RSAAKTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sess.NonceTPM(),
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicySecret: %v", err)
	}

	akResponse, err := tpm2.CreateLoaded{
		//ParentHandle: tpm2.TPMRHEndorsement,
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimaryEK.ObjectHandle,
			Name:   cPrimaryEK.Name,
			Auth:   sess,
		},
		InPublic: tpm2.New2BTemplate(&RSAAKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: akResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("Created AK Name :%s", hex.EncodeToString(akResponse.Name.Buffer))

	// now print out the PEM format of the RSA KEy
	akContents, err := akResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	akDetails, err := akContents.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	akUnique, err := akContents.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	akRSAPub, err := tpm2.RSAPub(akDetails, akUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	akPubDER, err := x509.MarshalPKIXPublicKey(akRSAPub)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	akPubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: akPubDER,
	}
	akPubPEM := pem.EncodeToMemory(akPubBlock)
	log.Printf("AK RSA Key \n%s\n", string(akPubPEM))

	log.Println("======= Attestor certifies ak with the duplicated key ========")
	//qualifyingData := []byte("foo")
	certifyResponse, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: akResponse.ObjectHandle,
			Name:   akResponse.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: loadedHmacKey.ObjectHandle,
			Name:   loadedHmacKey.Name,
		},
		// QualifyingData: tpm2.TPM2BData{
		// 	Buffer: qualifyingData,
		// },
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't certify key %v", err)
	}

	log.Println("======= Attestor sends attestation signature,attestation and the AK RSA Public key (akPubPEM) to Verifier ========")
	crs, err := certifyResponse.Signature.Signature.HMAC()
	if err != nil {
		log.Fatalf("can't certifyResponse signature %v", err)
	}
	log.Printf("Certify Response digest %s\n", base64.StdEncoding.EncodeToString(crs.Digest))

	cr, err := certifyResponse.CertifyInfo.Contents()
	if err != nil {
		log.Fatalf("can't certifyResponse contents %v", err)
	}

	cer, err := cr.Attested.Certify()
	if err != nil {
		log.Fatalf("can't read certifyinfo %v", err)
	}
	log.Println("======= verifier checks attesatation certification info specifications ========")
	log.Printf("Certify Firmware Version %d\n", int64(cr.FirmwareVersion))
	log.Printf("Certify AK Name %s\n", hex.EncodeToString(cer.Name.Buffer))
	log.Printf("Certify Extra Data %s\n", string(cr.ExtraData.Buffer))

	/// derive AK from template and the RSA Public key

	// first get the pulbic key from the akPEM sent over by the verifier
	blockPEM, _ := pem.Decode(akPubPEM)
	if blockPEM == nil {
		log.Fatal("failed to decode PEM block containing public key")
	}
	akPubVeriferPEMParsed, err := x509.ParsePKIXPublicKey(blockPEM.Bytes)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	pubKey := akPubVeriferPEMParsed.(*rsa.PublicKey)

	// you can derive the name from this and compare it to what was in the Certify.Name.Buffer above

	derivedRSAAKTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pubKey.N.Bytes(), // the verifier uses the AK Public key to renerate the 'name'
			},
		),
	}

	derivedName, err := tpm2.ObjectName(&derivedRSAAKTemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	log.Printf("Derived Name from rsa PublicKey %s", hex.EncodeToString(derivedName.Buffer))

	if bytes.Equal(derivedName.Buffer, cer.Name.Buffer) {
		log.Println("Attesation names match")
	} else {
		log.Fatal("attestation names do not match")
	}

	log.Println("======= Attestor verifies the HMAC signature of the attesation certification info  ========")

	ha := hmac.New(sha256.New, []byte(*keySensitive))
	attestHash := sha256.Sum256(certifyResponse.CertifyInfo.Bytes())
	ha.Write(attestHash[:])

	log.Printf("calculated hmac of attestation using local hmac key %s\n", base64.StdEncoding.EncodeToString(ha.Sum(nil)))

	if bytes.Equal(ha.Sum(nil), crs.Digest) {
		log.Println("attestation verified")
	} else {
		log.Fatalf("Invalid attestation")
	}

}
