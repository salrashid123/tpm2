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
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

/*
go snippet which uses policy signed and AES

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"

openssl genrsa -out private_key.pem 2048

What the following does is:

1. loads an external signing private key ("private_key.pem") from disk into a TPM
2. print the public/private key
3. create a PolicySigned policy where the signing authority is the private_key.pem and
    which stipulates a "policyRef" and expiration value of 30seconds to be part of the signature
4. create an aes key on the tpm with RSASRKTemplate as the parent and the policy signed defined previously
5. create a policy session
6. proivde the NonceTPM derived for that session to some signer

Suppose the signer only wants to authorize encryption of string: data := []byte("foooo")
   (yes, i know, its a contrived example)

7. the signer will create a CommandParameter hash value which is just the hash of all the command parameters which includes the string to sign,
    the name of the new rsa key

	the values of the command parameter are hashed to create the cpHashA value

8. the signer will take the noneTPM from step 6, the policyRefstring, the cpHashA and the expiration value to create a hash

              aHash ≔ sha256(nonceTPM || expiration || cpHashA || policyRef)

9. the signer will sign the aHash using key in step 1

10. the signer will give the signed aHash and aHash to the system with the TPM

11. The TPM will use the _same policy_ as in step 5 (since it includes the nonceTPM), then create a PolicySigned with
     the policyRef, expiration, CpHash and the signature from step 9

12. The tpm will use that session to encrypt some data


*/

const ()

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

	// bitSize := 2048

	// // Generate RSA key.
	// key, err := rsa.GenerateKey(rand.Reader, bitSize)
	// if err != nil {
	// 	panic(err)
	// }

	privateKeyPEM, err := os.ReadFile("private.pem")
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		return
	}

	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		fmt.Println("Failed to decode PEM block")
		return
	}

	rkey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes) // Or x509.ParsePKCS8PrivateKey
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	key := rkey.(*rsa.PrivateKey)

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
				// Scheme: tpm2.TPMTRSAScheme{
				// 	Scheme: tpm2.TPMAlgRSASSA,
				// 	Details: tpm2.NewTPMUAsymScheme(
				// 		tpm2.TPMAlgRSASSA,
				// 		&tpm2.TPMSSigSchemeRSASSA{
				// 			HashAlg: tpm2.TPMAlgSHA256,
				// 		},
				// 	),
				// },
				KeyBits: 2048,
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

	n, err := tpm2.ObjectName(&rsaTemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}
	log.Printf("loaded external %s\n", hex.EncodeToString(n.Buffer))

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

	log.Printf("======= create policysigned ========")

	policyRefString := "foobar"

	expirationTime := 30

	// ***********

	// **************

	_, err = tpm2.PolicySigned{
		PolicySession: sess.Handle(),
		AuthObject:    l.ObjectHandle,
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
						Buffer: pub.(*rsa.PublicKey).N.Bytes(),
					},
				},
			),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policysigned: %v", err)
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	/// ****************************

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

	// start a session
	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	// ************** recreate policysigned
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	// TPM2.0 spec, Revision 1.38, Part 3 nonce must be present if expiration is non-zero.
	// aHash ≔ HauthAlg(nonceTPM || expiration || cpHashA || policyRef)

	// now use the key to encrypt
	data := []byte("foooo")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalf("can't read rand %v", err)
	}

	// cpHashA: digest of the command parameters for the command being
	// approved using the hash algorithm of the policy session. Set to
	// an EmptyAuth if the authorization is not limited to a specific
	// command.

	f := tpm2.EncryptDecrypt2{
		KeyHandle: tpm2.AuthHandle{
			Name: aesKey.Name,
		},
		Message: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Decrypt: false,
		Mode:    tpm2.TPMAlgCFB,
		IV: tpm2.TPM2BIV{
			Buffer: iv,
		},
	}

	d, err := tpm2.CPHash(tpm2.TPMAlgSHA256, f)
	if err != nil {
		panic(err)
	}

	dgst := d.Buffer
	fmt.Printf("cphash: %s\n", hex.EncodeToString(dgst))

	//**

	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, uint32(expirationTime))
	toDigest := append(sess2.NonceTPM().Buffer, expBytes...)

	cpHash := dgst //[]byte{}
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
	log.Printf("Signature %s\n", hex.EncodeToString(sig))

	_, err = tpm2.PolicySigned{
		PolicySession: sess2.Handle(),
		AuthObject:    l.ObjectHandle,
		NonceTPM:      sess2.NonceTPM(),
		Expiration:    int32(expirationTime),
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: []byte(policyRefString),
		},
		CPHashA: tpm2.TPM2BDigest{Buffer: cpHash},
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
			Decrypt: decrypt,
			Mode:    tpm2.TPMAlgCFB,
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
