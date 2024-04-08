package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

/*
tpm2_evictcontrol -C o -c 0x81008001

tpm2_pcrread sha256:23

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat


tpm2_createprimary -C o -c primary.ctx
tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa.pub -r rsa.priv -C primary.ctx  -L policy.dat -p testpswd
tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx
tpm2_evictcontrol -C o -c rsa.ctx 0x81008001




tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx


echo "my message" > message.dat
tpm2_sign -c rsa.ctx -g sha256 -o sig.ecc message.dat  -p"session:session.dat+testpswd"
tpm2_verifysignature -c rsa.ctx -g sha256 -s sig.ecc -m message.dat


tpm2_flushcontext session.dat


tpm2_dictionarylockout --setup-parameters --max-tries=4294967295 --clear-lockout
*/

const (
	emptyPassword = ""
	objPassword   = "testpswd"
	pcrBank       = 23
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {

	flag.Parse()
	log.Println("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	pcrList := []int{pcrBank}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	// Extend PCR=23
	// err = tpm2.PCRExtend(rwc, pcrBank, tpm2.AlgSHA256, expectedDigest[:], emptyPassword)
	// if err != nil {
	// 	log.Fatalf("Unable to Extend PCR: %v", err)
	// }

	pkh := tpmutil.Handle(0x81008001)

	dataToSeal := []byte("secret")

	sessSignHandle, _, err := tpm2.StartAuthSession(
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
	defer tpm2.FlushContext(rwc, sessSignHandle)

	if err := tpm2.PolicyPCR(rwc, sessSignHandle, nil, pcrSelection); err != nil {
		log.Fatalf("unable to bind PCRs to auth policy: %v", err)
	}

	err = tpm2.PolicyPassword(rwc, sessSignHandle)
	if err != nil {
		log.Fatalf("Unable to create PolicyPassword : %v", err)
	}

	digest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSeal, tpm2.HandleOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hash failed unexpectedly: %v", err)
		return
	}

	sig, err := tpm2.SignWithSession(rwc, sessSignHandle, pkh, objPassword, digest[:], khValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Signing: %v", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Signature data:  %s\n", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

}
