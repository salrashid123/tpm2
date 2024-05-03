package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	hmacKey = "change this password to a secret"
)

var (
	tpmPath      = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	newParentPub = flag.String("new-parent", "new-parent.pub", "New Parents public key")
	dupPub       = flag.String("duppub", "dup.pub", "dup public")
	dupDup       = flag.String("dupdup", "dup.dup", "dup duplicate")
	dupSeed      = flag.String("dupseed", "dup.seed", "dup seed file")
)

func main() {

	flag.Parse()
	log.Println("======= Init  ========")

	rwc, err := tpmutil.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary ========")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		// CreationPCR: tpm2.TPMLPCRSelection{
		// 	PCRSelections: []tpm2.TPMSPCRSelection{
		// 		{
		// 			Hash:      tpm2.TPMAlgSHA256,
		// 			PCRSelect: tpm2.PCClientCompatible.PCRs(23),
		// 		},
		// 	},
		// },
	}
	if err != nil {
		log.Fatalf("Error creating EK: %v", err)
	}

	cPrimary, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err := flush.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	log.Printf("Name %s\n", hex.EncodeToString(cPrimary.Name.Buffer))

	log.Printf("======= createHMAC ========")

	newParentBytes, err := os.ReadFile(*newParentPub)
	if err != nil {
		log.Fatalf("can't read new parent %q: %v", *tpmPath, err)
	}

	policy, err := dupPolicyDigest(rwr)
	if err != nil {
		log.Fatalf("can't create policy digest %q: %v", *tpmPath, err)
	}

	createLoadedReq := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: false,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{
								HashAlg: tpm2.TPMAlgSHA256,
							}),
					},
				}),
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: nil,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: []byte(hmacKey),
				}),
			},
		},
	}

	createLoadedResp, err := createLoadedReq.Execute(rwr)
	if err != nil {
		log.Fatalf("can't createload %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createLoadedResp.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	pub2, err := tpm2.Unmarshal[tpm2.TPMTPublic](newParentBytes)
	if err != nil {
		log.Fatalf(" Unmarshal unmarshall new parent to tpmpublic %q: %v", *tpmPath, err)
	}

	newParentLoadcmd := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHOwner,
		InPublic:  tpm2.New2B(*pub2),
	}

	err = os.WriteFile(*dupPub, createLoadedResp.OutPublic.Bytes(), 0644)
	if err != nil {
		log.Fatalf("can't write public to  file %q: %v", *tpmPath, err)
	}
	// tpm2.FlushContext{FlushHandle: createLoadedResp.ObjectHandle}.Execute(rwr)

	rsp, err := newParentLoadcmd.Execute(rwr)
	if err != nil {
		log.Fatalf(" newParentLoadcmd can't close TPM %q: %v", *tpmPath, err)
	}

	duplicateResp, err := tpm2.Duplicate{
		ObjectHandle: tpm2.AuthHandle{
			Handle: createLoadedResp.ObjectHandle,
			Name:   createLoadedResp.Name,
			Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, tpm2.PolicyCallback(func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
				_, err := tpm2.PolicyCommandCode{
					PolicySession: handle,
					Code:          tpm2.TPMCCDuplicate,
				}.Execute(tpm)
				return err
			})),
		},
		NewParentHandle: tpm2.NamedHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
		},
		Symmetric: tpm2.TPMTSymDef{
			Algorithm: tpm2.TPMAlgNull,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("duplicateResp can't close TPM %q: %v", *tpmPath, err)
	}

	err = os.WriteFile(*dupSeed, duplicateResp.OutSymSeed.Buffer, 0644)
	if err != nil {
		log.Fatalf("can't write duplicatesymseed to file %q: %v", *tpmPath, err)
	}

	// tpm2_print -t TPMT_PUBLIC dup.pub
	err = os.WriteFile(*dupDup, duplicateResp.Duplicate.Buffer, 0644)
	if err != nil {
		log.Fatalf("can't writing duplicate duplicate %q: %v", *tpmPath, err)
	}
	if _, err = (tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(rwr); err != nil {
		log.Fatalf(" FlushContext can't close TPM %q: %v", *tpmPath, err)
	}
}

func dupPolicyDigest(thetpm transport.TPM) ([]byte, error) {
	sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer cleanup()

	_, err = tpm2.PolicyCommandCode{
		PolicySession: sess.Handle(),
		Code:          tpm2.TPMCCDuplicate,
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	return pgd.PolicyDigest.Buffer, nil
}
