package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
go snippet which uses policy signed and RSA

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"

openssl genrsa -out private_key.pem 2048

What the following does is:

1. loads an external signing private key ("private_key.pem") from disk into a TPM
2. print the public/private key
3. create a PolicySigned policy where the signing authority is the public part of private_key.pem and
    which stipulates a "policyRef" and expiration value of 30seconds to be part of the signature
4. create an RSA key on the tpm (or duplicate+transfer) with RSASRKTemplate as the parent and the policysigned defined previously
5. create a policy session
6. proivde the NonceTPM derived for that session to some signer

>>> NOTE: what this flow allows for is for a remote authorizer (eg, the one with the private_key.pem), to authorize only specific data to get signed

Suppose the signer only wants to authorize signing of string: data := []byte("foooo")

7. the signer will create a CommandParameter hash value which is just the hash of all the command parameters which includes the string to sign,
    and the name of the new rsa key

	the values of the command parameter are hashed to create the cpHashA value

8. the signer will take the noneTPM from step 6, the policyRefstring, the cpHashA and the expiration value to create a hash

              aHash ≔ sha256(nonceTPM || expiration || cpHashA || policyRef)

9. the signer will sign the aHash using key in step 1

10. the signer will give the signed aHash and aHash to the system with the TPM

11. The TPM will use the _same policy_ as in step 5 (since it includes the nonceTPM), then create a PolicySigned with
     the policyRef, expiration, CpHash and the signature from step 9

12. The tpm will use that session to sign


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

	// first load the private key
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

	// now load the signing external public key into the tpm.
	// note public key.N is set to the unique
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

	// load the signing key
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

	// first create primary key for the new rsa key
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

	// now create a policysession
	//  into which we will create policy signed
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

	// create a policy sesison with specific conditions
	//  1. the signing expires in 30 seconds (expireTime)
	//  2. the policy has a opaque string assigned to it (policyRef)
	//  3. the policysigned is bound to the public part of `private_key.pem`
	log.Printf("======= create policysigned ========")

	policyRefString := "foobar"
	expirationTime := 30

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
	keyRSATemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: pgd.PolicyDigest,
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
	}

	// create the bound rsakey
	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(keyRSATemplate),
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

	// now we want to sign so we load it
	krsaKey, err := tpm2.Load{
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
			FlushHandle: krsaKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	fmt.Printf("Key Name from create %s\n", hex.EncodeToString(krsaKey.Name.Buffer))

	// start a session
	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	// just extract the PEM of the key we just created (this is not the public part of `private_key.pem`)

	c, err := cCreate.OutPublic.Contents()
	if err != nil {
		log.Fatalf("error reading rsa public %v", err)
	}

	rsaDetail, err := c.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("error reading rsa public %v", err)
	}
	rsaUnique, err := c.Unique.RSA()
	if err != nil {
		log.Fatalf("error reading rsa unique %v", err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	b, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	fmt.Printf("Generated PEM \n%s\n", string(publicKeyPEM))

	// now printe out the 'name' of the imported key
	//  since we know the template used and the unique part

	u := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPub.N.Bytes(),
		},
	)

	keyRSATemplate.Unique = u

	n, err := tpm2.ObjectName(&keyRSATemplate)
	if err != nil {
		log.Fatalf("Failed to get name key: %v", err)
	}

	fmt.Printf("Name of the Authorizing Signing Key %s\n", hex.EncodeToString(n.Buffer))

	// ************** recreate the bit we need to sign remotely

	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	// TPM2.0 spec, Revision 1.38, Part 3 nonce must be present if expiration is non-zero.
	// aHash ≔ HauthAlg(nonceTPM || expiration || cpHashA || policyRef)

	// so, we want to stipulate what we want to sign can only be 'foooo'
	data := []byte("foooo")
	digest := sha256.Sum256(data)

	// now create a signing structure with all the parameter
	f := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			//Name: krsaKey.Name,  // yes, in this code we could've just done this instead of regenerating the name since we can do this remotely
			Name: tpm2.TPM2BName{
				Buffer: n.Buffer,
			},
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
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

	// generate the comman parameter hash including the 'name'
	d, err := tpm2.CPHash(tpm2.TPMAlgSHA256, f)
	if err != nil {
		log.Fatalf("%v", err)
	}

	dgst := d.Buffer
	fmt.Printf("cphash: %s\n", hex.EncodeToString(dgst))

	// ******************************

	//  now create
	// aHash ≔ HauthAlg(nonceTPM || expiration || cpHashA || policyRef)
	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, uint32(expirationTime))
	toDigest := append(sess2.NonceTPM().Buffer, expBytes...)

	cpHash := dgst //[]byte{}  // if the cpHahs is nil, then anything can be signe
	toDigest = append(toDigest, cpHash...)
	policyRef := []byte(policyRefString)
	toDigest = append(toDigest, policyRef...)

	msgHash := sha256.New()
	_, err = msgHash.Write(toDigest)
	if err != nil {
		log.Fatalf("%v", err)
	}
	aHash := msgHash.Sum(nil)

	// now sign aHash
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, aHash)
	if err != nil {
		log.Fatalf("error executing sign: %v", err)
	}
	log.Printf("Authorization Signature %s\n", base64.StdEncoding.EncodeToString(sig))

	// ok, now we're ready to actually insert the remotely signed bits into the policysigned for real
	_, err = tpm2.PolicySigned{
		PolicySession: sess2.Handle(),        // remember this is the same session where we used the noncetpm as part of the signature
		AuthObject:    l.ObjectHandle,        // this is the loaded external rsa key
		NonceTPM:      sess2.NonceTPM(),      // this is the nonce tpm for the session
		Expiration:    int32(expirationTime), // remember to set the same expiration time
		PolicyRef: tpm2.TPM2BNonce{
			Buffer: []byte(policyRefString), // remember to use the same polcy ref
		},
		CPHashA: tpm2.TPM2BDigest{Buffer: cpHash},
		Auth: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig: tpm2.TPM2BPublicKeyRSA{
						Buffer: sig, /// insert the signature here
					},
				},
			),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policysigned: %v", err)
	}

	// now use the initialized policy to sign

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: krsaKey.ObjectHandle,
			Name:   krsaKey.Name,
			Auth:   sess2,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
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
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}

	s, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("error getting rsassa signature %s", err)
	}

	log.Printf("TPM Signature %s", base64.StdEncoding.EncodeToString(s.Sig.Buffer))

}
