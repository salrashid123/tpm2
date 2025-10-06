package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

/*
Derive EK and AK

tpm2_createek -c ek.handle -G rsa -u ek.pub

$ go run main.go
2025/10/04 02:28:15 ======= EK ========
2025/10/04 02:28:15 Name 000b69865f79ea7d98508047341ca0e296d59d307f97adb698552baa9278c70e3648
2025/10/04 02:28:15 RSA createPrimary public
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwwu+DsqgxuU719c7qJDT
SkQ17a8uCIeka2IOrgI3dxFkKlLp608W+CmL2LF2zfHmqDTC58i9vePzP0RYd1i1
DZjBTZZaYKef9q/RNwJut39rHp97Zbhm2R+kdffDtjPUuOUZgrO0UHXakFL4C3Gd
6Dl6DUOqCTFcmD+pzZKMrMm18q+uGQA5FiPvBDSACyleNdDJw1QGi+fU4dl4P6lQ
fpnvFQZU+Ra2DR7nfNtlqs7MAf3msblNBcdZBGS3wxeqELYsJNEUGjDVOqZwazgO
WKtQ9SSe7Duju3dk5bcz2T15pxEHeBWOLXQFA/eP3vMVOdNT81Y3TmvoDUfJTdK5
EwIDAQAB
-----END PUBLIC KEY-----

2025/10/04 02:28:15 ======= createPrimary RSAEKTemplate ========
2025/10/04 02:28:15 Name 000b69865f79ea7d98508047341ca0e296d59d307f97adb698552baa9278c70e3648
2025/10/04 02:28:15 GCE EKPublic:
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwwu+DsqgxuU719c7qJDT
SkQ17a8uCIeka2IOrgI3dxFkKlLp608W+CmL2LF2zfHmqDTC58i9vePzP0RYd1i1
DZjBTZZaYKef9q/RNwJut39rHp97Zbhm2R+kdffDtjPUuOUZgrO0UHXakFL4C3Gd
6Dl6DUOqCTFcmD+pzZKMrMm18q+uGQA5FiPvBDSACyleNdDJw1QGi+fU4dl4P6lQ
fpnvFQZU+Ra2DR7nfNtlqs7MAf3msblNBcdZBGS3wxeqELYsJNEUGjDVOqZwazgO
WKtQ9SSe7Duju3dk5bcz2T15pxEHeBWOLXQFA/eP3vMVOdNT81Y3TmvoDUfJTdK5
EwIDAQAB
-----END PUBLIC KEY-----

2025/10/04 02:28:15 RSA Key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsDZy+XCSluw8/kGMXNSS
0cF54oKWNsHoPhSTgtcPhuCwwps40tSr/LGd4eKo7Pu6gEB/LAbTbtN2VAeM4vfa
DNQtK2039ZnPvr/ketEDzH7+qg07Ll4bVlSrewt+rwWTluQ2VAdwt4tikDwxqWPf
aSmHrHAqn5VM8w8XmjdeAumYl5xpe9q8RZgEhe5KzBbdDWk3K725k+Ym8wgfv+yH
7RUhM8A2fYkzXpSGPsMIZcCA5v1AC0FKRYbG+GP+SWQ/GDh8DVKv1QP4gZt16kXW
qd1fCfNsHHMjqeeVBaqI6Im9iU6dxmwu5NO2WQC+46bk4HCMHAVRAPPWuRSD4wom
iQIDAQAB
-----END PUBLIC KEY-----

$ tpm2_readpublic -c ek.handle
name: 000b69865f79ea7d98508047341ca0e296d59d307f97adb698552baa9278c70e3648
qualified name: 000bd532751ababd73ec3481cfdc74adfb9b24e40ea87fbf04389b6c238a0622624d
name-alg:

	value: sha256
	raw: 0xb

attributes:

	value: fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt
	raw: 0x300b2

type:

	value: rsa
	raw: 0x1

exponent: 65537
bits: 2048
scheme:

	value: null
	raw: 0x10

scheme-halg:

	value: (null)
	raw: 0x0

sym-alg:

	value: aes
	raw: 0x6

sym-mode:

	value: cfb
	raw: 0x43

sym-keybits: 128
rsa: c30bbe0ecaa0c6e53bd7d73ba890d34a4435edaf2e0887a46b620eae02377711642a52e9eb4f16f8298bd8b176cdf1e6a834c2e7c8bdbde3f33f44587758b50d98c14d965a60a79ff6afd137026eb77f6b1e9f7b65b866d91fa475f7c3b633d4b8e51982b3b45075da9052f80b719de8397a0d43aa09315c983fa9cd928cacc9b5f2afae1900391623ef0434800b295e35d0c9c354068be7d4e1d9783fa9507e99ef150654f916b60d1ee77cdb65aacecc01fde6b1b94d05c7590464b7c317aa10b62c24d1141a30d53aa6706b380e58ab50f5249eec3ba3bb7764e5b733d93d79a7110778158e2d740503f78fdef31539d353f356374e6be80d47c94dd2b913
authorization policy: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
*/
const (

	// RSA 2048 EK Cert.
	EKCertNVIndexRSA uint32 = 0x01c00002
	// ECC P256 EK Cert.
	EKCertNVIndexECC uint32 = 0x01c0000a

	EKReservedHandle uint32 = 0x81010001
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")

	RSAAKTemplate = tpm2.TPMTPublic{
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

	// *************************

	// start externally managed
	// managed externally, this will block all other access to the tpm
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

	log.Printf("======= EK ========")

	// read from handle
	// EKReservedHandle uint32 = 0x81010001
	cCreateEK, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(EKReservedHandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}
	log.Printf("Name %s\n", hex.EncodeToString(cCreateEK.Name.Buffer))

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

	log.Printf("RSA createPrimary public \n%s\n", string(primaryEKPEMByte))

	log.Printf("======= createPrimary RSAEKTemplate ========")

	// read from template
	cCreateGCEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateGCEEK.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	// // read from handle
	// cCreateGCEEK, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(EKReservedHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create object TPM %q: %v", *tpmPath, err)
	// }
	log.Printf("Name %s\n", hex.EncodeToString(cCreateGCEEK.Name.Buffer))

	rsaaEKpub, err := cCreateGCEEK.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rsaaEKDetail, err := rsaaEKpub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rsaaEKUnique, err := rsaaEKpub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	primaryaRsaEKPub, err := tpm2.RSAPub(rsaaEKDetail, rsaaEKUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	b4a, err := x509.MarshalPKIXPublicKey(primaryaRsaEKPub)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	blockb := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b4a,
	}
	primaryEKPEMByteb := pem.EncodeToMemory(blockb)
	log.Printf("GCE EKPublic: \n%s\n", string(primaryEKPEMByteb))

	/// **************************************

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

	// // verify the digest
	// pgd, err := tpm2.PolicyGetDigest{
	// 	PolicySession: sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing PolicyGetDigest: %v", err)
	// }

	rsaKeyResponsea, err := tpm2.CreateLoaded{
		//ParentHandle: tpm2.TPMRHEndorsement,
		ParentHandle: tpm2.AuthHandle{
			Handle: cCreateGCEEK.ObjectHandle,
			Name:   cCreateGCEEK.Name,
			Auth:   sess,
		},
		InPublic: tpm2.New2BTemplate(&RSAAKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponsea.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rpuba, err := rsaKeyResponsea.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rrsaDetaila, err := rpuba.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rrsaUniquea, err := rpuba.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	rrsaPuba, err := tpm2.RSAPub(rrsaDetaila, rrsaUniquea)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	b4aa, err := x509.MarshalPKIXPublicKey(rrsaPuba)
	if err != nil {
		log.Fatalf("Unable to convert rsaGCEAKPub: %v", err)
	}

	blocka := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b4aa,
	}
	keyPEMBytea := pem.EncodeToMemory(blocka)
	log.Printf("RSA Key \n%s\n", string(keyPEMBytea))
}
