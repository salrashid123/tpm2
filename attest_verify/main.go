package main

import (
	"bytes"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"

	//"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/legacy/tpm2"
)

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	confirmGCESEV = flag.Bool("confirmGCESEV", false, "Confirm if GCE SEV Status is active")
	eventLogPath  = flag.String("eventLogPath", "/sys/kernel/security/tpm0/binary_bios_measurements", "Path to the eventlog")
)

func main() {
	flag.Parse()

	var err error

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}
	defer ekk.Close()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer ak.Close()

	nonce := []byte("noncevalue")

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		log.Fatalf("failed to attest: %v", err)
	}

	//ims, err := server.VerifyAttestation(attestation, server.VerifyOpts{
	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	})
	if err != nil {
		log.Fatalf("failed to verify: %v", err)
	}
	log.Printf("Attestation Verified")
	//log.Printf("Machine State: %v", ims.RawEvents)

	log.Printf("=============== Parsing EventLog ===============")

	el, err := attest.ParseEventLog(attestation.EventLog)
	if err != nil {
		log.Printf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	sb, err := attest.ParseSecurebootState(el.Events(attest.HashSHA1))
	if err != nil {
		log.Printf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	log.Printf("     secureBoot State enabled %t", sb.Enabled)

	if *confirmGCESEV {
		log.Printf("     PCR and eventlogs verified, assessing SEV Status for GCE:")
		for _, e := range el.Events(attest.HashSHA256) {
			// eventTypes aren't exported enums https://github.com/google/go-attestation/blob/master/attest/internal/events.go#L70
			// so match as string
			// review: https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md#event-type-and-verification-footguns
			//   https://trustedcomputinggroup.org/wp-content/uploads/TCG-Guidance-Integrity-Measurements-Event-Log-Processing_v1_r0p118_24feb2022-1.pdf
			if e.Index == 0 && e.Type.String() == "EV_NONHOST_INFO" {
				sevStatus, err := parseGCENonHostInfo(e.Data)
				if err != nil {
					log.Printf("Error parsing SEV Status: %v", err)
					os.Exit(1)
				}
				log.Printf("     EV SevStatus: %s\n", sevStatus.String())
			}
		}
	}

}

// from https://github.com/google/go-tpm-tools/blob/master/server/policy_constants.go#L162
func parseGCENonHostInfo(nonHostInfo []byte) (attestpb.GCEConfidentialTechnology, error) {
	prefixLen := len(server.GCENonHostInfoSignature)
	if len(nonHostInfo) < (prefixLen + 1) {
		return attestpb.GCEConfidentialTechnology_NONE, fmt.Errorf("length of GCE Non-Host info (%d) is too short", len(nonHostInfo))
	}

	if !bytes.Equal(nonHostInfo[:prefixLen], server.GCENonHostInfoSignature) {
		return attestpb.GCEConfidentialTechnology_NONE, errors.New("prefix for GCE Non-Host info is missing")
	}
	tech := nonHostInfo[prefixLen]
	if tech > byte(attestpb.GCEConfidentialTechnology_AMD_SEV_SNP) || tech == byte(3) {
		return attestpb.GCEConfidentialTechnology_NONE, fmt.Errorf("unknown GCE Confidential Technology: %d", tech)
	}
	return attestpb.GCEConfidentialTechnology(tech), nil
}
