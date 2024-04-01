package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/client"
	//"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	flush   = flag.String("flush", "all", "Flush existing handles")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	keyParametersCreatedECC = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
				os.Exit(1)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	pcrList := []int{0}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, pkh)
	privInternal, pubArea, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, keyParametersCreatedECC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
		os.Exit(1)
	}
	newHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, newHandle)

	fmt.Printf("======= Sign with new ECC ========\n")
	dataToSeal := []byte("secret")

	digest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSeal, tpm2.HandleOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hash failed unexpectedly: %v", err)
		return
	}

	sig, err := tpm2.Sign(rwc, newHandle, "", digest[:], khValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Signing: %v", err)
	}

	utPub, err := tpm2.DecodePublic(pubArea)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error DecodePublic AK %v", utPub)
		return
	}
	uap, err := utPub.Key()
	if err != nil {
		fmt.Fprintf(os.Stderr, "akPub.Key() failed: %s", err)
		return
	}
	uBytes, err := x509.MarshalPKIXPublicKey(uap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to convert akPub: %v", err)
		return
	}

	uakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: uBytes,
		},
	)
	fmt.Printf("ECC Signing Key \n%s\n", string(uakPubPEM))

	epub := uap.(*ecdsa.PublicKey)

	curveBits := epub.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}
	out := make([]byte, 2*keyBytes)
	sig.ECC.R.FillBytes(out[0:keyBytes])
	sig.ECC.S.FillBytes(out[keyBytes:])

	fmt.Fprintf(os.Stderr, "Signature data:  %s\n", base64.RawStdEncoding.EncodeToString(out))

	hsh := crypto.SHA256.New()
	hsh.Write(dataToSeal)
	block, _ := pem.Decode(uakPubPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Unable to decode akPubPEM %v", err)
		return
	}

	ok := ecdsa.Verify(epub, digest[:], epub.X, epub.Y)
	if !ok {
		fmt.Printf("ECDSA Signed String failed\n")
	}
	fmt.Printf("ECDSA Signed String verified\n")

}
