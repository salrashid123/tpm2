package main

import (
	"bytes"
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

const ()

var (
	tpmPath = flag.String("tpm-path", "simulator", "Path to the TPM device (character device or a Unix socket).")
	secret  = flag.String("secret", "meet me at...", "secret")
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

	log.Println("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary RSAEKTemplate ========")

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", hex.EncodeToString(primaryKey.Name.Buffer))

	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rsaPub.N.Bytes(),
	}
	primaryPEMByte := pem.EncodeToMemory(block)
	log.Printf("RSA Primary \n%s\n", string(primaryPEMByte))

	// rsa

	// rsaTemplate := tpm2.TPMTPublic{
	// 	Type:    tpm2.TPMAlgRSA,
	// 	NameAlg: tpm2.TPMAlgSHA256,
	// 	ObjectAttributes: tpm2.TPMAObject{
	// 		SignEncrypt:         true,
	// 		FixedTPM:            true,
	// 		FixedParent:         true,
	// 		SensitiveDataOrigin: true,
	// 		UserWithAuth:        true,
	// 		Restricted:          true,
	// 	},
	// 	AuthPolicy: tpm2.TPM2BDigest{},
	// 	Parameters: tpm2.NewTPMUPublicParms(
	// 		tpm2.TPMAlgRSA,
	// 		&tpm2.TPMSRSAParms{
	// 			Scheme: tpm2.TPMTRSAScheme{
	// 				Scheme: tpm2.TPMAlgRSASSA,
	// 				Details: tpm2.NewTPMUAsymScheme(
	// 					tpm2.TPMAlgRSASSA,
	// 					&tpm2.TPMSSigSchemeRSASSA{
	// 						HashAlg: tpm2.TPMAlgSHA256,
	// 					},
	// 				),
	// 			},
	// 			KeyBits: 2048,
	// 		},
	// 	),
	// }

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		cleanup1()

	}()

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

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   sess,
		},
		InPublic: tpm2.New2BTemplate(&tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rpub, err := rsaKeyResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get rsa public: %v", err)
	}
	rrsaDetail, err := rpub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	rrsaUnique, err := rpub.Unique.RSA()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	rrsaPub, err := tpm2.RSAPub(rrsaDetail, rrsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rrsaPub.N.Bytes(),
	}
	keyPEMByte := pem.EncodeToMemory(block)
	log.Printf("RSA Key \n%s\n", string(keyPEMByte))

	keyPublicBytes := rsaKeyResponse.OutPublic.Bytes()

	rsaPubBuf := rsaKeyResponse.OutPublic.Bytes()
	rsaPrivBuf := rsaKeyResponse.OutPrivate.Buffer

	// ***** close everything
	cleanup1()

	flushContextCmdKey := tpm2.FlushContext{
		FlushHandle: rsaKeyResponse.ObjectHandle,
	}
	_, _ = flushContextCmdKey.Execute(rwr)
	flushContextCmdPrimary := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmdPrimary.Execute(rwr)

	// *****************************************************

	secret := tpm2.TPM2BDigest{Buffer: []byte(*secret)}

	loadedPrimary, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](primaryKey.OutPublic.Bytes()),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}
	log.Printf("key Primary Name: %v\n", hex.EncodeToString(loadedPrimary.Name.Buffer))

	loadedKey, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](keyPublicBytes),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}

	log.Printf("key Name: %v\n", hex.EncodeToString(loadedKey.Name.Buffer))
	mc, err := tpm2.MakeCredential{
		Handle:      loadedPrimary.ObjectHandle,
		Credential:  secret,
		ObjectNamae: loadedKey.Name,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create makecredential %v", err)
	}

	// alternatively get name from the public key

	// u := tpm2.NewTPMUPublicID(
	// 	tpm2.TPMAlgRSA,
	// 	&tpm2.TPM2BPublicKeyRSA{
	// 		Buffer: rrsaPub.N.Bytes(),
	// 	},
	// )

	// keyPububFromPEMTemplate := tpm2.RSAEKTemplate
	// keyPububFromPEMTemplate.Unique = u

	// na, err := tpm2.ObjectName(&keyPububFromPEMTemplate)
	// if err != nil {
	// 	log.Fatalf("Failed to get name key: %v", err)
	// }

	// log.Printf("key Name: %v\n", hex.EncodeToString(na.Buffer))
	// *************** make credential

	// mc, err := tpm2.MakeCredential{
	// 	Handle:      primaryKey.ObjectHandle,
	// 	Credential:  secret,
	// 	ObjectNamae: *na,
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create makecredential %v", err)
	// }

	// ***** close everything

	flushContextCmdKey2 := tpm2.FlushContext{
		FlushHandle: loadedKey.ObjectHandle,
	}
	_, _ = flushContextCmdKey2.Execute(rwr)
	flushContextCmdPrimary2 := tpm2.FlushContext{
		FlushHandle: loadedPrimary.ObjectHandle,
	}
	_, _ = flushContextCmdPrimary2.Execute(rwr)

	/// ============================ =================================================================================================

	log.Printf("======= Activate ========")

	primaryKey2, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey2.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	loadedKey2, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey2.ObjectHandle,
			Name:   primaryKey2.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](rsaPubBuf),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: rsaPrivBuf,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load key2 %v", err)
	}
	log.Printf("key Primary Name: %v\n", hex.EncodeToString(loadedKey2.Name.Buffer))

	// sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	// if err != nil {
	// 	log.Fatalf("setting up trial session: %v", err)
	// }
	// defer func() {
	// 	if err := cleanup2(); err != nil {
	// 		log.Fatalf("cleaning up trial session: %v", err)
	// 	}
	// }()

	// _, err = tpm2.PolicySecret{
	// 	AuthHandle:    tpm2.TPMRHEndorsement,
	// 	NonceTPM:      sess2.NonceTPM(),
	// 	PolicySession: sess2.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing PolicySecret: %v", err)
	// }

	acRsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: loadedKey2.ObjectHandle,
			Name:   loadedKey2.Name,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: primaryKey2.ObjectHandle,
			Name:   primaryKey2.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy), // sess2
		},
		CredentialBlob: mc.CredentialBlob,
		Secret:         mc.Secret,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create activate %v", err)
	}

	if !bytes.Equal(acRsp.CertInfo.Buffer, secret.Buffer) {
		log.Fatalf("want %x got %x", secret.Buffer, acRsp.CertInfo.Buffer)
	}

}

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}
