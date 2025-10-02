package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpmsigner"
)

var (
	servercert = flag.String("servercert", "ECcert.pem", "Server certificate (x509)")
	tpmPath    = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")

	cn       = flag.String("cn", "foooo", "(required) CN= value for the certificate")
	filename = flag.String("filename", "csr.pem", "Filename to save the generated csr")
	sni      = flag.String("sni", "server.domain.com", "SNI value in the csr generated csr")
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
		ObjectHandle: tpm2.TPMHandle(0x81010001),
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

	pubPEMData, err := os.ReadFile(*servercert)

	if err != nil {
		log.Fatalf("can't load  certificate : %v", err)
	}

	sblock, _ := pem.Decode(pubPEMData)
	if err != nil {
		log.Fatalf("can't decode  certificate : %v", err)
	}

	filex509, err := x509.ParseCertificate(sblock.Bytes)
	if err != nil {
		log.Fatalf("can't parse  certificate : %v", err)
	}

	se, err := tpmsigner.NewPolicySecretSession(rwr, tpm2.AuthHandle{
		Handle: tpm2.TPMRHEndorsement,
		Auth:   tpm2.PasswordAuth([]byte(nil))}, 0)
	if err != nil {
		log.Fatalf("can't parse  certificate : %v", err)
	}
	r, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice:       rwc,
		Handle:          tpm2.TPMHandle(0x81010001), //cCreateEK.ObjectHandle,
		X509Certificate: filex509,
		AuthSession:     se,
	})
	if err != nil {
		log.Fatal(err)
	}

	err = createCSR(r)
	if err != nil {
		log.Fatal(err)
	}
}

func createCSR(t crypto.Signer) error {

	log.Printf("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         *cn,
		},
		DNSNames: []string{*sni},
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, t)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}
	certOut, err := os.Create(*filename)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", *filename, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("Failed to write data to %s: %s", *filename, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s  %s", *filename, err)
	}
	log.Printf("wrote %s\n", *filename)

	return nil
}
