package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/salrashid123/tpm2genkey/util"
)

const ()

var (
	tpmPath    = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyFile    = flag.String("keyfile", "private.pem", "privateKey File")
	dataToSign = flag.String("datatosign", "bar", "data to sign")
	password   = flag.String("password", "", "key password")
	pcrs       = flag.String("pcrs", "", "pcr banks to bind the key to")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get() //GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

type TPM struct {
	transport io.ReadWriteCloser
}

func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

func getTPM(s io.ReadWriteCloser) (transport.TPMCloser, error) {
	return &TPM{

		transport: s,
	}, nil
}

func (t *TPM) Close() error {
	return t.transport.Close()
}

func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	// load the rsa key from disk
	log.Printf("======= creating key ========")

	rwr := transport.FromReadWriter(rwc)

	// setup the key template

	csess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.AESEncryption(128, tpm2.EncryptOut)}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1()

	uintpcrs := make([]uint, len(strings.Split(*pcrs, ",")))
	for idx, i := range strings.Split(*pcrs, ",") {
		if i != "" {
			j, err := strconv.Atoi(i)
			if err != nil {
				log.Fatalf("tpm2genkey: error converting pcr list  %v\n", err)

			}
			uintpcrs[idx] = uint(j)
		}
	}

	var commandParameterPCR []byte
	var commandParameterAuth []byte
	if len(*pcrs) > 0 {
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uintpcrs...),
				},
			},
		}

		expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
		if err != nil {
			log.Fatalf("ERROR:  could not get PolicySession: %v", err)
		}

		pol := tpm2.PolicyPCR{
			PolicySession: csess.Handle(),
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: expectedDigest,
			},
		}

		_, err = pol.Execute(rwr)
		if err != nil {
			log.Fatalf("error executing PolicyPCR: %v", err)
		}

		// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
		// pcrSelectionSegment := tpm2.Marshal(sel)
		// pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		// 	Buffer: expectedDigest,
		// })
		// commandParameterPCR = append(pcrDigestSegment, pcrSelectionSegment...)

		commandParameterPCR, err = util.CPBytes(pol)
		if err != nil {
			log.Fatalf("error getting policy command bytes: %v", err)
		}

	}
	if len(*password) > 0 {
		_, err = tpm2.PolicyAuthValue{
			PolicySession: csess.Handle(),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("error executing PolicyAuthValue: %v", err)
		}
		commandParameterAuth, err = util.CPBytes(tpm2.PolicyAuthValue{PolicySession: csess.Handle()})
		if err != nil {
			log.Fatalf("error getting policy command bytes: %v", err)
		}
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: csess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	keyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: pgd.PolicyDigest.Buffer,
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
				KeyBits:  tpm2.TPMKeyBits(2048),
				Exponent: uint32(65537),
			},
		),
	}

	var pol []*keyfile.TPMPolicy

	if len(*pcrs) > 0 {
		pol = append(pol, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyPCR),
			CommandPolicy: commandParameterPCR,
		})
	}

	if len(*password) > 0 {
		pol = append(pol, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
			CommandPolicy: commandParameterAuth,
		})
	}

	cprimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint(tpm2.TPMRHOwner.HandleValue())),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: nil,
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create primary: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cprimary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	keyresponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: cprimary.ObjectHandle,
			Name:   cprimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(*password),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create key: %v", err)
	}

	kf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		keyresponse.OutPublic,
		keyresponse.OutPrivate,
		keyfile.WithParent(tpm2.TPMHandle(uint(tpm2.TPMRHOwner.HandleValue()))),
		keyfile.WithUserAuth([]byte(*password)),

		keyfile.WithPolicy(pol),
	)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create key bytes: %v", err)
	}

	flushContextCmdc := tpm2.FlushContext{
		FlushHandle: cprimary.ObjectHandle,
	}
	_, err = flushContextCmdc.Execute(rwr)

	cleanup1()

	log.Printf("=======  key created ========")
	key, err := keyfile.Decode(keyFileBytes.Bytes())
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	rwrc, err := getTPM(rwc)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}
	sess := keyfile.NewTPMSession(rwrc)
	sess.SetOpt(tpm2.Password([]byte(nil)))
	//log.Printf("Parent is TPM_HT_PERMANENT: %t", keyfile.IsMSO(tpm2.TPMHandle(key.Parent), keyfile.TPM_HT_PERMANENT))
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: key.Parent,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("failed loading key with parent: %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	parentAuthHandle := tpm2.AuthHandle{
		Handle: primary.ObjectHandle,
		Name:   primary.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}
	ah, err := keyfile.LoadKeyWithParent(sess, parentAuthHandle, key)
	if err != nil {
		log.Fatalf("failed loading key with parent: %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ah.Handle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	data := []byte(*dataToSign)
	digest := sha256.Sum256(data)

	psess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(*password))}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			log.Fatalf("cleaning up trial session: %v", err)
		}
	}()

	for _, ppol := range key.Policy {
		switch cc := ppol.CommandCode; cc {
		case int(tpm2.TPMCCPolicyPCR):
			// TPM2BDigest struct section 10.4.2 https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
			//    size UINT16
			//    buffer[size]{:sizeof(TPMU_HA)} BYTE

			policy := &tpm2.PolicyPCR{
				PolicySession: psess.Handle(),
			}

			err = util.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up policypcr: %v", err)
			}

			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up policypcr: %v", err)
			}

			// // get the length of the digest, first 2bytes is length of buffer
			// l := binary.BigEndian.Uint16(ppol.CommandPolicy[:2])
			// dgst := ppol.CommandPolicy[:l+2]

			// d, err := tpm2.Unmarshal[tpm2.TPM2BDigest](dgst)
			// if err != nil {
			// 	log.Fatalf("error unmarshal TPM2BDigest: %v", err)
			// }

			// tc, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](ppol.CommandPolicy[l+2:]) // digest includes 2 byte size prefix
			// if err != nil {
			// 	log.Fatalf("error unmarshalling TPMLPCRSelection: %v", err)
			// }
			// _, err = tpm2.PolicyPCR{
			// 	PolicySession: psess.Handle(),
			// 	PcrDigest:     *d,
			// 	Pcrs:          *tc,
			// }.Execute(rwr)
			// if err != nil {
			// 	log.Fatalf("setting up policypcr: %v", err)
			// }

		case int(tpm2.TPMCCPolicyAuthValue):

			policy := &tpm2.PolicyAuthValue{
				PolicySession: psess.Handle(),
			}

			err = util.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up policyauthvalue: %v", err)
			}

			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up policyauthvalue: %v", err)
			}

			// _, err = tpm2.PolicyAuthValue{
			// 	PolicySession: psess.Handle(),
			// }.Execute(rwr)
			// if err != nil {
			// 	log.Fatalf("setting up policyauthvalue: %v", err)
			// }
		default:
			log.Fatalf("Unsupported command parameter")
		}
	}

	var tkeyH tpm2.AuthHandle

	if len(key.Policy) == 0 || key.EmptyAuth {
		tkeyH = tpm2.AuthHandle{
			Handle: ah.Handle,
			Name:   ah.Name,
			Auth:   tpm2.PasswordAuth(nil),
		}
	} else {
		tkeyH = tpm2.AuthHandle{
			Handle: ah.Handle,
			Name:   ah.Name,
			Auth:   psess,
		}
	}

	rspSign, err := tpm2.Sign{
		KeyHandle: tkeyH,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature  : %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))
}

func getExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}
