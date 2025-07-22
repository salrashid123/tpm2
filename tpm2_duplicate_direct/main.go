package main

import (
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
	"os"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
		// } else if path == "simulator" {
		// 	return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	// ************************

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	b, err := os.ReadFile("ek.pem")
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	publicKey, _ := pem.Decode(b)

	p, err := x509.ParsePKIXPublicKey(publicKey.Bytes)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	ekrsaPub, ok := p.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Failed to get public")
	}

	u := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: ekrsaPub.N.Bytes(),
		},
	)

	ekPububFromPEMTemplate := tpm2.RSAEKTemplate
	ekPububFromPEMTemplate.Unique = u

	// ********************************************

	rk, err := os.ReadFile("key_rsa.pem")
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	publicKeyRK, _ := pem.Decode(rk)

	rsaPriv, err := x509.ParsePKCS1PrivateKey(publicKeyRK.Bytes)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	data := []byte("This is the data to be signed.")

	// 3. Hash the data
	hashed := sha256.Sum256(data)

	// 4. Sign the hash using PKCS1v15 padding
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing data:", err)
		return
	}

	fmt.Printf("Signature: %s\n", base64.StdEncoding.EncodeToString(signature))

	// createImportBlobHelper

	rsaPub := rsaPriv.PublicKey

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
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
				Exponent: uint32(rsaPub.E),
				KeyBits:  2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		),
	}

	sens := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		AuthValue: tpm2.TPM2BAuth{
			Buffer: nil,
		},
		SeedValue: tpm2.TPM2BDigest{
			Buffer: nil,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPriv.Primes[0].Bytes()},
		),
	}
	sens2B := tpm2.Marshal(sens)

	packedSecret := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	var seed, encryptedSeed []byte

	ek, err := ekPububFromPEMTemplate.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

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

	h, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		log.Fatalf("Failed ek.Scheme.Scheme.Hash: %v", err)
	}
	encryptedSeed, err = rsa.EncryptOAEP(
		h.New(),
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

	//  end createRSASeed

	// start createDuplicate
	// https://github.com/google/go-tpm/blob/11143c1b847cf950eda07e547bca2be31b1d920c/legacy/tpm2/structures.go#L79

	name, err := tpm2.ObjectName(&rsaTemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	nameEncoded := name.Buffer

	fmt.Printf("RSAPublic Name %s\n", hex.EncodeToString(nameEncoded))

	ekbi, err := ek.Symmetric.KeyBits.AES()
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	symSize := int(*ekbi)

	h2, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		log.Fatalf("Failed ek.Scheme.Scheme.Hash: %v", err)
	}

	symmetricKey := tpm2.KDFa(
		h2,
		seed,
		"STORAGE",
		nameEncoded,
		/*contextV=*/ nil,
		symSize)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	encryptedSecret := make([]byte, len(packedSecret))
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encryptedSecret, packedSecret)
	// end encryptSecret

	// start createHMAC
	h3, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		log.Fatalf("Failed ek.Scheme.Scheme.Hash: %v", err)
	}

	macKey := tpm2.KDFa(
		h3,
		seed,
		"INTEGRITY",
		/*contextU=*/ nil,
		/*contextV=*/ nil,
		h3.New().Size()*8)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	mac := hmac.New(func() hash.Hash { return h.New() }, macKey)
	mac.Write(encryptedSecret)
	mac.Write(nameEncoded)
	hmacSum := mac.Sum(nil)
	// end createHMAC

	dup := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: hmacSum})
	dup = append(dup, encryptedSecret...)

	pubEncoded := tpm2.Marshal(&rsaTemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	/// *********************************************************************************************

	// first create a session on the TPM which will allow use of the EK.
	//  using EK here needs PolicySecret

	cPrimary, err := tpm2.CreatePrimary{
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
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flush.Execute(rwr)
	}()

	/// *********

	rsaEKpub, err := cPrimary.OutPublic.Contents()
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

	log.Printf("RSA createPrimary public \n%s\n", string(primaryEKPEMByte))

	/// *********

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

	dupPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubEncoded)
	if err != nil {
		log.Fatalf("Failed Unmarshal: %v", err)
	}

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
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
		log.Fatalf("FailedImport: %v", err)
	}
	err = import_session_cleanup()
	if err != nil {
		log.Fatalf("Failed cleanup: %v", err)
	}

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

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
			Auth:   load_sess,
		},
		InPublic:  tpm2.New2B(rsaTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: hashed[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

}
