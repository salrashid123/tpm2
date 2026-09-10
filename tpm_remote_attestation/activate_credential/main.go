package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

var (
	akKeyFile           = flag.String("akKeyFile", "output/ak.pem", "file to read the akkeyfile")
	encryptedSecretFile = flag.String("encryptedSecret", "output/encryptedSecret.bin", "encryptedSecret Blob File")

	credentialBlobFile = flag.String("credentialBlobFile", "output/credentialblob.bin", "Credential Blob File")
	tpmPath            = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")

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

func main() {
	flag.Parse()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

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

	c, err := os.ReadFile(*akKeyFile)
	if err != nil {
		log.Fatalf("can't load keys %q: %v", *tpmPath, err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("can't decode keys %q: %v", *tpmPath, err)
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

	akKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   sess,
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		log.Fatalf("can't load  hmacKey : %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: akKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	cb, err := os.ReadFile(*credentialBlobFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	ec, err := os.ReadFile(*encryptedSecretFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return
	}

	cleanup1()
	acRsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: akKey.ObjectHandle,
			Name:   akKey.Name,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy), // sess2
		},
		CredentialBlob: tpm2.TPM2BIDObject{
			Buffer: cb,
		},
		Secret: tpm2.TPM2BEncryptedSecret{
			Buffer: ec,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create activate %v", err)
	}

	fmt.Printf("%s\n", string(acRsp.CertInfo.Buffer))

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
