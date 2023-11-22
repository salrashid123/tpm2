package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

/*

crate parent, child, grandchild all bound to policypassword and a specific pcr value
use the grandchild to encrypt/decrypt

	   $ tpm2_pcrread sha256:0,23
	     sha256:
	       0 : 0xD0C70A9310CD0B55767084333022CE53F42BEFBB69C059EE6C0A32766F160783
	       23: 0x0000000000000000000000000000000000000000000000000000000000000000


	   ## to mutate the pcr value
	   $ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

	   $ tpm2_pcrread sha256:0,23
	     sha256:
	       0 : 0xD0C70A9310CD0B55767084333022CE53F42BEFBB69C059EE6C0A32766F160783
	       23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

  go run . --mode=create
  go run . --mode=load

*/

const (
	rootP           = ""
	defaultPassword = ""
	parentP         = "foo"
	childP          = "bar"
	grandchildP     = "qux"

	cPub          = "childPub.bin"
	cPriv         = "childPriv.bin"
	gPub          = "grandchildPub.bin"
	gPriv         = "grandchildPriv.bin"
	encryptedData = "encrypteddata.bin"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	mode = flag.String("mode", "create", "create or load")

	plaintext = flag.String("plaintext", "hello world", "plaintext to encrypt")

	flush      = flag.String("flush", "none", "Flush contexts, must be oneof transient|saved|loaded|all")
	pcrsValues = flag.String("pcrValues", "0=d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783,23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b", "SHA256 PCR Values to seal against 23=foo,20=bar.")
	pcrMap     = map[uint32][]byte{}

	dataToSign = []byte("secret")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	primaryTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		AuthPolicy: []byte(defaultPassword),
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	childTepmplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
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

	grandchildTemplate = tpm2.Public{
		Type:    tpm2.AlgSymCipher,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagSign |
			tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
		AuthPolicy: []byte{},
		SymCipherParameters: &tpm2.SymCipherParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
		},
	}
)

func main() {

	flag.Parse()

	data := []byte(*plaintext)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("error creating iv %v\n", err)
	}


	log.Println("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %s: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("\ncan't close TPM %s: %v", *tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "getting handles: %v", err)
			return
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stderr, "flushing handle 0x%x: %v", handle, err)
				return
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	pcrMap := make(map[uint32][]byte)

	entries := strings.Split(*pcrsValues, ",")
	var pcrRegisters []int
	for _, e := range entries {
		parts := strings.Split(e, "=")
		u, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error flushing handle  %v\n", err)
			os.Exit(1)
		}

		hv, err := hex.DecodeString(parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error flushing handle  %v\n", err)
			os.Exit(1)
		}
		pcrMap[uint32(u)] = hv
		pcrRegisters = append(pcrRegisters, int(u))
	}

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrRegisters}

	pcrval, err := tpm2.ReadPCRs(rwc, pcrSelection)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to ReadPCR: %v", err)
		os.Exit(1)
	}

	var expectedVal []byte
	for _, pcr := range pcrSelection.PCRs {
		fmt.Printf("PCR:value %d:%s\n", pcr, hex.EncodeToString(pcrval[pcr]))
		expectedVal = append(expectedVal, pcrval[pcr]...)
	}

	expectedDigest := sha256.Sum256(expectedVal)

	if *mode == "create" {
		fmt.Printf("======= CreatePrimary ========\n")
		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, rootP, parentP, primaryTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		// defer tpm2.FlushContext(rwc, pkh)

		fmt.Printf("======= Create Child ========\n")

		sessCreateChildHandle, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, sha256.Size),
			nil,
			tpm2.SessionTrial,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create StartAuthSession : %v", err)
			os.Exit(1)
		}

		if err := tpm2.PolicyPCR(rwc, sessCreateChildHandle, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		policyVal, err := tpm2.PolicyGetDigest(rwc, sessCreateChildHandle)
		if err != nil {
			log.Fatalf("Unable to create PolicyPassword : %v", err)
		}
		fmt.Printf("Starting Policy Digest %s\n", hex.EncodeToString(policyVal))

		childTepmplate.AuthPolicy = policyVal

		childpriv, childpub, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, parentP, childP, childTepmplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
			os.Exit(1)
		}

		childHandle, _, err := tpm2.Load(rwc, pkh, parentP, childpub, childpriv)
		if err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}

		tpm2.FlushContext(rwc, sessCreateChildHandle)
		tpm2.FlushContext(rwc, pkh)

		err = os.WriteFile(cPub, childpub, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childPub failed for childFile%v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(cPriv, childpriv, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "childriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		fmt.Printf("======= Create GrandChild ========\n")

		sessCreateGrandChildHandle, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, sha256.Size),
			nil,
			tpm2.SessionTrial,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create StartAuthSession : %v", err)
			os.Exit(1)
		}

		if err := tpm2.PolicyPassword(rwc, sessCreateGrandChildHandle); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		if err := tpm2.PolicyPCR(rwc, sessCreateGrandChildHandle, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		policyValGrandChild, err := tpm2.PolicyGetDigest(rwc, sessCreateGrandChildHandle)
		if err != nil {
			log.Fatalf("Unable to create PolicyPassword : %v", err)
		}
		fmt.Printf("Starting Policy Digest %s\n", hex.EncodeToString(policyVal))

		grandchildTemplate.AuthPolicy = policyValGrandChild

		grandchildpriv, grandchildpub, _, _, _, err := tpm2.CreateKey(rwc, childHandle, pcrSelection, childP, grandchildP, grandchildTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
			os.Exit(1)
		}

		grandchildHandle, _, err := tpm2.Load(rwc, childHandle, childP, grandchildpub, grandchildpriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading  key %v\n", err)
			os.Exit(1)
		}

		tpm2.FlushContext(rwc, childHandle)
		tpm2.FlushContext(rwc, sessCreateGrandChildHandle)

		err = os.WriteFile(gPub, grandchildpub, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grandchildpub failed for childFile%v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(gPriv, grandchildpriv, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grandchildpriv failed for childFile%v\n", err)
			os.Exit(1)
		}

		// fmt.Printf("======= Encrypt with GrandChild ========\n")

		sessUseGrandChildHandleEncrypt, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, sha256.Size),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, sessUseGrandChildHandleEncrypt)

		if err := tpm2.PolicyPassword(rwc, sessUseGrandChildHandleEncrypt); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		if err := tpm2.PolicyPCR(rwc, sessUseGrandChildHandleEncrypt, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}

		encrypted, err := EncryptSymmetricWithSession(rwc, sessUseGrandChildHandleEncrypt, grandchildP, grandchildHandle, iv, data)
		if err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}

		encrypted = append(iv,encrypted...)

		log.Printf("Encrypted %s", base64.StdEncoding.EncodeToString(encrypted))

		tpm2.FlushContext(rwc, sessUseGrandChildHandleEncrypt)

		err = os.WriteFile(encryptedData, encrypted, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "writing encrypted data failed%v\n", err)
			os.Exit(1)
		}



		tpm2.FlushContext(rwc, grandchildHandle)
	}

	if *mode == "load" {

		// load all the files

		childpub, err := os.ReadFile(cPub)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}
		childpriv, err := os.ReadFile(cPriv)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		grandchildpub, err := os.ReadFile(gPub)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}
		grandchildpriv, err := os.ReadFile(gPriv)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		fmt.Printf("======= CreatePrimary ========\n")
		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, rootP, parentP, primaryTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		// defer tpm2.FlushContext(rwc, pkh)

		fmt.Printf("======= Load Child ========\n")

		sessCreateChildHandle, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, sha256.Size),
			nil,
			tpm2.SessionTrial,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create StartAuthSession : %v", err)
			os.Exit(1)
		}

		if err := tpm2.PolicyPCR(rwc, sessCreateChildHandle, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		policyVal, err := tpm2.PolicyGetDigest(rwc, sessCreateChildHandle)
		if err != nil {
			log.Fatalf("Unable to create PolicyPassword : %v", err)
		}
		fmt.Printf("Starting Policy Digest %s\n", hex.EncodeToString(policyVal))

		childTepmplate.AuthPolicy = policyVal

		childHandle, _, err := tpm2.Load(rwc, pkh, parentP, childpub, childpriv)
		if err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}

		tpm2.FlushContext(rwc, sessCreateChildHandle)
		tpm2.FlushContext(rwc, pkh)

		fmt.Printf("======= Load GrandChild ========\n")

		sessCreateGrandChildHandle, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, sha256.Size),
			nil,
			tpm2.SessionTrial,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create StartAuthSession : %v", err)
			os.Exit(1)
		}

		if err := tpm2.PolicyPassword(rwc, sessCreateGrandChildHandle); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		if err := tpm2.PolicyPCR(rwc, sessCreateGrandChildHandle, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		policyValGrandChild, err := tpm2.PolicyGetDigest(rwc, sessCreateGrandChildHandle)
		if err != nil {
			log.Fatalf("Unable to create PolicyPassword : %v", err)
		}
		fmt.Printf("Starting Policy Digest %s\n", hex.EncodeToString(policyVal))

		grandchildTemplate.AuthPolicy = policyValGrandChild

		grandchildHandle, _, err := tpm2.Load(rwc, childHandle, childP, grandchildpub, grandchildpriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading  key %v\n", err)
			os.Exit(1)
		}

		tpm2.FlushContext(rwc, childHandle)
		tpm2.FlushContext(rwc, sessCreateGrandChildHandle)

		encrypted, err := os.ReadFile(encryptedData)
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		sessUseGrandChildHandleDecrypt, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, sha256.Size),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, sessUseGrandChildHandleDecrypt)

		if err := tpm2.PolicyPassword(rwc, sessUseGrandChildHandleDecrypt); err != nil {
			log.Fatalf("unable to bind PCRs to session: %v", err)
		}

		if err := tpm2.PolicyPCR(rwc, sessUseGrandChildHandleDecrypt, expectedDigest[:] /*nil*/, pcrSelection); err != nil {
			fmt.Printf("Error %s\n", err)
			os.Exit(1)
		}

		decrypted, err := DecryptSymmetricWithSession(rwc, sessUseGrandChildHandleDecrypt, grandchildP, grandchildHandle,encrypted[:aes.BlockSize], encrypted[aes.BlockSize:])
		if err != nil {
			log.Fatalf("DecryptSymmetric failed: %s", err)
		}

		log.Printf("Decrypted %s", string(decrypted))
		tpm2.FlushContext(rwc, sessUseGrandChildHandleDecrypt)
		tpm2.FlushContext(rwc, grandchildHandle)

	}

}

func DecryptSymmetricWithSession(rw io.ReadWriteCloser, sessionHandle tpmutil.Handle, keyAuth string, key tpmutil.Handle, iv, data []byte) ([]byte, error) {
	return encryptDecryptSymmetric(rw, sessionHandle, keyAuth, key, iv, data, true)
}

const (
	maxDigestBuffer = 1024
)

func EncryptSymmetricWithSession(rw io.ReadWriteCloser, sessionHandle tpmutil.Handle, keyAuth string, key tpmutil.Handle, iv, data []byte) ([]byte, error) {
	return encryptDecryptSymmetric(rw, sessionHandle, keyAuth, key, iv, data, false)
}

func encryptDecryptSymmetric(rw io.ReadWriteCloser, sessionHandle tpmutil.Handle, keyAuth string, key tpmutil.Handle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte
	var err error

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		block, iv, err = encryptDecryptBlockSymmetric(rw, sessionHandle, keyAuth, key, iv, block, decrypt)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}

	return out, nil
}

func encryptDecryptBlockSymmetric(rw io.ReadWriteCloser, sessionHandle tpmutil.Handle, keyAuth string, key tpmutil.Handle, iv, data []byte, decrypt bool) ([]byte, []byte, error) {
	Cmd, err := encodeEncryptDecrypt2(sessionHandle, keyAuth, key, iv, data, decrypt)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, tpm2.TagSessions, tpm2.CmdEncryptDecrypt2, tpmutil.RawBytes(Cmd))
	if err != nil {
		fmt0Err, ok := err.(tpm2.Error)
		if ok && fmt0Err.Code == tpm2.RCCommandCode {
			// If TPM2_EncryptDecrypt2 is not supported, fall back to
			// TPM2_EncryptDecrypt.
			Cmd, _ := encodeEncryptDecrypt(sessionHandle, keyAuth, key, iv, data, decrypt)
			resp, err = runCommand(rw, tpm2.TagSessions, tpm2.CmdEncryptDecrypt, tpmutil.RawBytes(Cmd))
			if err != nil {
				return nil, nil, err
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	return decodeEncryptDecrypt(resp)
}

func decodeEncryptDecrypt(resp []byte) ([]byte, []byte, error) {
	var paramSize uint32
	var out, nextIV tpmutil.U16Bytes
	if _, err := tpmutil.Unpack(resp, &paramSize, &out, &nextIV); err != nil {
		return nil, nil, err
	}
	return out, nextIV, nil
}

func encodeEncryptDecrypt(sessionHandle tpmutil.Handle, keyAuth string, key tpmutil.Handle, iv, data tpmutil.U16Bytes, decrypt bool) ([]byte, error) {
	ha, err := tpmutil.Pack(key)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: sessionHandle, Attributes: tpm2.AttrContinueSession, Auth: []byte(keyAuth)})
	if err != nil {
		return nil, err
	}
	// Use encryption key's mode.
	params, err := tpmutil.Pack(decrypt, tpm2.AlgNull, iv, data)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

func encodeEncryptDecrypt2(sessionHandle tpmutil.Handle, keyAuth string, key tpmutil.Handle, iv, data tpmutil.U16Bytes, decrypt bool) ([]byte, error) {
	ha, err := tpmutil.Pack(key)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: sessionHandle, Attributes: tpm2.AttrContinueSession, Auth: []byte(keyAuth)})
	if err != nil {
		return nil, err
	}
	// Use encryption key's mode.
	params, err := tpmutil.Pack(data, decrypt, tpm2.AlgNull, iv)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

func encodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
}

