package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
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

var (
	secret              = flag.String("secret", "meet me at...", "secret")
	akKeyFile           = flag.String("akKeyFile", "output/ak.pem", "file to read the akkeyfile")
	quotedFile          = flag.String("quotedFile", "output/quoted.bin", "file to write the quoteResponse")
	quotedSignatureFile = flag.String("quotedSignatureFile", "output/quotedsignature.bin", "file to write the quoteSignature")
	tpmPath             = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pcr                 = flag.Int("pcr", 23, "PCR to seal data to. Must be within [0, 23].")
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

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(23),
			},
		},
	}

	q, err := tpm2.Quote{
		SignHandle: tpm2.NamedHandle{
			Handle: akKey.ObjectHandle,
			Name:   akKey.Name,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: []byte(*secret),
		},
		PCRSelect: sel,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	ppub, err := tpm2.ReadPublic{
		ObjectHandle: akKey.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error reading  handle public %v", err)
	}

	pub, err := ppub.OutPublic.Contents()
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

	// 	type QuoteResponse struct {
	// 	// the quoted information
	// 	Quoted TPM2BAttest
	// 	// the signature over quoted
	// 	Signature TPMTSignature
	// }

	err = os.WriteFile(*quotedFile, q.Quoted.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*quotedSignatureFile, tpm2.Marshal(q.Signature), 0644)
	if err != nil {
		log.Fatal(err)
	}

	// q2, err := tpm2.Unmarshal[tpm2.TPMSAttest, *tpm2.TPMSAttest](q.Quoted.Bytes())
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Printf("attestation secret:   [%s]", string(q2.ExtraData.Buffer))

	// sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](tpm2.Marshal(q.Signature))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// rsassa, err := sig.Signature.RSASSA()

	att, err := q.Quoted.Contents()
	if err != nil {
		log.Fatalf("Failed to getting attestation: %v", err)
	}
	log.Printf("attestation secret:   [%s]", string(att.ExtraData.Buffer))

	rsassa, err := q.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

	digest := sha256.Sum256([]byte(q.Quoted.Bytes()))

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer); err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	log.Printf("verified")
}
