package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

// rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
//     sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
//     sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

// export TPM2TOOLS_TCTI="swtpm:port=2321"
// tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
// $ tpm2_pcrread sha256:23
//   sha256:
//     23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

const (
	pcr = 23
)

const (
	keyPassword = "keypwd"
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
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

	log.Printf("======= createPrimary ========")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}
	if err != nil {
		log.Fatalf("Error creating primary: %v", err)
	}

	cPrimary, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	log.Printf("======= create ========")

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			log.Fatalf("cleaning up trial session: %v", err)
		}
	}()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
			},
		},
	}

	expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
	if err != nil {
		log.Printf("ERROR:  could not get PolicySession: %v", err)
		return
	}

	// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	pcrSelectionSegment := tpm2.Marshal(sel)
	pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		Buffer: expectedDigest,
	})

	commandParameter := append(pcrDigestSegment, pcrSelectionSegment...)
	// 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
	log.Printf("pcrSelectionSegment %s", hex.EncodeToString(pcrSelectionSegment))
	log.Printf("pcrDigestSegment %s", hex.EncodeToString(pcrDigestSegment))

	log.Printf("commandParameter %s", hex.EncodeToString(commandParameter))

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing policyAuthValue: %v", err)
	}

	// verify the digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest: %v", err)
	}

	aesTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			Decrypt:             true,
			SignEncrypt:         true,
		},
		AuthPolicy: pgd.PolicyDigest,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
				},
			},
		),
	}

	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(aesTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(keyPassword),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create object TPM  %v", err)
	}

	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	data := []byte("foooo")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalf("can't read rand %v", err)
	}

	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(keyPassword))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	// _, err = tpm2.PolicyPCR{
	// 	PolicySession: sess2.Handle(),
	// 	Pcrs: tpm2.TPMLPCRSelection{
	// 		PCRSelections: sel.PCRSelections,
	// 	},
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("executing policyAuthValue: %v", err)
	// }

	// _, err = tpm2.PolicyAuthValue{
	// 	PolicySession: sess2.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("executing policyAuthValue: %v", err)
	// }

	// TPM2BDigest struct section 10.4.2 https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
	//    size UINT16
	//    buffer[size]{:sizeof(TPMU_HA)} BYTE

	// get the length of the digest, first 2bytes is length of buffer
	l := binary.BigEndian.Uint16(commandParameter[:2])
	dgst := commandParameter[:l+2]

	d, err := tpm2.Unmarshal[tpm2.TPM2BDigest](dgst)
	if err != nil {
		log.Fatalf("setting up policy TPM2BDigest: %v", err)
	}

	t, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](commandParameter[l+2:])
	if err != nil {
		log.Fatalf("setting up policy TPMLPCRSelection: %v", err)
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
		PcrDigest:     *d,
		Pcrs:          *t,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing policyAuthValue: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess2.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing policyAuthValue: %v", err)
	}

	keyAuth2 := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   sess2,
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth2, iv, data, false)

	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	log.Printf("IV: %s", hex.EncodeToString(iv))
	log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

	sess3, cleanup3, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(keyPassword))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup3()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess3.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing policyAuthValue: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess3.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("executing policyAuthValue: %v", err)
	}

	keyAuth3 := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   sess3,
	}

	decrypted, err := encryptDecryptSymmetric(rwr, keyAuth3, iv, encrypted, true)
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}

	log.Printf("Decrypted %s", string(decrypted))

}

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCFB,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
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
