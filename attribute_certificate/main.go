package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"time"

	"github.com/google/go-attestation/attributecert"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
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
	platformCACertBytes, err := os.ReadFile("platform-ca.crt")
	if err != nil {
		log.Fatalf("ERROR: Unable to load paltform CA %v", err)
	}
	platformCAKeyBytes, err := os.ReadFile("platform-ca.key")
	if err != nil {
		log.Fatalf("ERROR: Unable to load paltform CA Key %v", err)
	}

	pubBlock, _ := pem.Decode(platformCACertBytes)
	ccacrt, err := x509.ParseCertificate(pubBlock.Bytes)
	if err != nil {
		log.Fatalf("error parsing client ca certificate %v", err)
	}

	privBlock, _ := pem.Decode(platformCAKeyBytes)
	ccakey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("error decoding client ca certificate ca key:  %v", err)
	}
	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 1)

	// h := &attributecert.Certholder{
	// 	Issuer: ek.Certificate.Issuer,
	// 	Serial: ek.Certificate.SerialNumber,
	// }

	ekBytes, err := os.ReadFile("ECcert.pem")
	if err != nil {
		log.Fatalf("ERROR: Unable to load paltform CA %v", err)
	}

	ekpubBlock, _ := pem.Decode(ekBytes)
	ek, err := x509.ParseCertificate(ekpubBlock.Bytes)
	if err != nil {
		log.Fatalf("error parsing client ca certificate %v", err)
	}

	log.Printf("EKCert's serial number %s", ek.SerialNumber)
	rdns := ek.Issuer.ToRDNSequence()
	derBytes, err := asn1.Marshal(rdns)
	if err != nil {
		log.Fatalf("ERROR:Failed to marshal RDNSequence to DER: %v", err)
	}

	acc, err := attributecert.CreateAttributeCertificate(derBytes, ek.SerialNumber, notBefore, notAfter, ccacrt, ccakey)
	if err != nil {
		log.Fatalf("ERROR:Failed to marshal RDNSequence to DER: %v", err)
	}

	log.Printf("======= AttributCertificate ========")

	certFile := "ascert.pem"

	// Create the output file
	file, err := os.Create(certFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var pemBlock = &pem.Block{
		Type:  "ATTRIBUTE CERTIFICATE", //
		Bytes: acc,                     // The DER encoded bytes of the certificate
	}
	if err := pem.Encode(file, pemBlock); err != nil {
		log.Fatal(err)
	}

	ac, err := attributecert.ParseAttributeCertificate(acc)
	if err != nil {
		log.Fatalf("Error  failed to parse  attribute certificate  %v", err)
	}

	log.Printf("     PlatformCertificate Issuer: %s\n", ac.Issuer)
	log.Printf("     PlatformCertificate Version: %d\n", ac.Version)

	log.Printf("     PlatformCertificate CredentialSpecification: %s\n", ac.CredentialSpecification)
	log.Printf("     PlatformCertificate PlatformManufacturer: %s\n", ac.PlatformManufacturer)
	log.Printf("     PlatformCertificate PlatformModel: %s\n", ac.PlatformModel)
	log.Printf("     PlatformCertificate PlatformVersion: %s\n", ac.PlatformVersion)
	log.Printf("     PlatformCertificate PropertiesURI: %s\n", ac.PropertiesURI)

	for j, c := range ac.Components {
		log.Printf("        PlatformCertificate Components[%d].Manufacturer: %s\n", j, c.Manufacturer)
		log.Printf("        PlatformCertificate Components[%d].ManufacturerID: %d\n", j, c.ManufacturerID)
		log.Printf("        PlatformCertificate Components[%d].Model: %s\n", j, c.Model)
		log.Printf("        PlatformCertificate Components[%d].Revision: %s\n", j, c.Revision)
		log.Printf("        PlatformCertificate Components[%d].Serial: %s\n", j, c.Serial)
		for i, a := range c.Addresses {
			log.Printf("        PlatformCertificate Components[%d].Addresses[%d].AddressType: %s\n", j, i, a.AddressType)
			log.Printf("        PlatformCertificate Components[%d].Addresses[%d].AddressValue: %s\n", j, i, a.AddressValue)
		}
		log.Printf("        PlatformCertificate Components[%d].FieldReplaceable: %t\n", j, c.FieldReplaceable)
	}

	log.Printf("     PlatformCertificate Holder.Issuer: %s\n", ac.Holder.Issuer)
	log.Printf("     PlatformCertificate Holder.Serial: %d\n", ac.Holder.Serial)
	log.Printf("     PlatformCertificate Holder.Issuer.CommonName: %s\n", ac.Holder.Issuer.CommonName)

	for i, p := range ac.Properties {
		log.Printf("        PlatformCertificate Properties[%d]. Name [%s] Value [%s]\n", i, p.PropertyName, p.PropertyValue)
	}
	log.Printf("     PlatformCertificate TBBSecurityAssertions.Iso9000URI: %s\n", ac.TBBSecurityAssertions.Iso9000URI)
	log.Printf("     PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: %s\n", ac.TBBSecurityAssertions.CcInfo.ProfileOid)
	log.Printf("     PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: %s\n", ac.TBBSecurityAssertions.CcInfo.ProfileURI)
	log.Printf("     PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: %s\n", ac.TBBSecurityAssertions.CcInfo.TargetOid)
	log.Printf("     PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: %s\n", ac.TBBSecurityAssertions.CcInfo.TargetURI)
	log.Printf("     PlatformCertificate TBBSecurityAssertions.CcInfo.Version: %s\n", ac.TBBSecurityAssertions.CcInfo.Version)

	log.Printf("     PlatformCertificate TCGPlatformSpecification.Version: %d\n", ac.TCGPlatformSpecification.Version)
	log.Printf("     PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: %d\n", ac.TCGPlatformSpecification.Version.MajorVersion)
	log.Printf("     PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: %d\n", ac.TCGPlatformSpecification.Version.MinorVersion)
	log.Printf("     PlatformCertificate TCGPlatformSpecification.Version.Revision: %d\n", ac.TCGPlatformSpecification.Version.Revision)

	log.Printf("     PlatformCertificate UserNotice.UserNotice.ExplicitText: %s\n", ac.UserNotice.ExplicitText)
	log.Printf("     PlatformCertificate UserNotice.UserNotice.Organization: %s\n", ac.UserNotice.NoticeRef.Organization)
	log.Printf("     PlatformCertificate UserNotice.UserNotice.NoticeNumbers: %d\n", ac.UserNotice.NoticeRef.NoticeNumbers)

	err = ac.CheckSignatureFrom(ccacrt)
	if err != nil {
		log.Fatalf("Error failed to verify  attribute certificate  %v", err)
	}
	log.Printf(" Verified Platform cert signed by privacyCA")

	log.Printf(" Platform Cert's Holder SerialNumber %s\n", ac.Holder.Serial)

}
