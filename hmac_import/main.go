package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword                   = ""
	CmdHmacStart    tpmutil.Command = 0x0000015B
	defaultPassword                 = ""
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	mode          = flag.String("mode", "sign", "import or sign")
	secret        = flag.String("secret", "change this password to a secret", "HMAC key to seal")
	primaryHandle = flag.String("primaryHandle", "primary.bin", "Handle to the primary")
	hmacKeyHandle = flag.String("hmacKeyHandle", "hmac.bin", "Handle to the primary")
	data          = flag.String("data", "foo", "Data to HMAC")
	flush         = flag.String("flush", "all", "Data to HMAC")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
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

	pcrList := []int{}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	if *mode == "import" {

		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, pkh)

		fmt.Printf("======= ContextSave (primary) ========\n")
		pkhBytes, err := tpm2.ContextSave(rwc, pkh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for pkh %v\n", err)
			os.Exit(1)
		}

		// err = tpm2.FlushContext(rwc, pkh)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
		// 	os.Exit(1)
		// }
		err = ioutil.WriteFile(*primaryHandle, pkhBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
			os.Exit(1)
		}

		// pkh, err = tpm2.ContextLoad(rwc, pkhBytes)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "ContextLoad failed for pkh %v\n", err)
		// 	os.Exit(1)
		// }

		public := tpm2.Public{
			Type:       tpm2.AlgKeyedHash,
			NameAlg:    tpm2.AlgSHA256,
			AuthPolicy: []byte(defaultPassword),
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagSign, // | tpm2.FlagSensitiveDataOrigin
			KeyedHashParameters: &tpm2.KeyedHashParams{
				Alg:  tpm2.AlgHMAC,
				Hash: tpm2.AlgSHA256,
			},
		}

		hmacKeyBytes := []byte(*secret)
		privInternal, pubArea, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, public, hmacKeyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  creating Sensitive %v\n", err)
			os.Exit(1)
		}
		newHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, newHandle)

		fmt.Printf("======= ContextSave (newHandle) ========\n")
		ekhBytes, err := tpm2.ContextSave(rwc, newHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for ekh %v\n", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(*hmacKeyHandle, ekhBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for ekh%v\n", err)
			os.Exit(1)
		}

		// pHandle := tpmutil.Handle(0x81010002)
		// err = tpm2.EvictControl(rwc, defaultPassword, tpm2.HandleOwner, newHandle, pHandle)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "Error  persisting hash key  %v\n", err)
		// 	os.Exit(1)
		// }
		// defer tpm2.FlushContext(rwc, pHandle)

		err = tpm2.FlushContext(rwc, newHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  flush hash key  %v\n", err)
			os.Exit(1)
		}

	} else if *mode == "sign" {

		fmt.Printf("======= ContextLoad (newHandle) ========\n")
		ekhBytes, err := ioutil.ReadFile(*hmacKeyHandle)
		if err != nil {
			fmt.Printf("ContextLoad failed for ekh: %v", err)
			fmt.Fprintf(os.Stderr, "ContextLoad failed for ekh %v\n", err)
			os.Exit(1)
		}
		newHandle, err := tpm2.ContextLoad(rwc, ekhBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextLoad failed for ekh: %v\n", err)
			os.Exit(1)
		}

		maxDigestBuffer := 1024
		//seqAuth := ""
		seq, err := HmacStart(rwc, defaultPassword, newHandle, tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  starting hash sequence %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, seq)

		plain := []byte(*data)
		for len(plain) > maxDigestBuffer {
			if err = tpm2.SequenceUpdate(rwc, defaultPassword, seq, plain[:maxDigestBuffer]); err != nil {
				fmt.Fprintf(os.Stderr, "Error  updating hash sequence %v\n", err)
				os.Exit(1)
			}
			plain = plain[maxDigestBuffer:]
		}

		digest, _, err := tpm2.SequenceComplete(rwc, defaultPassword, seq, tpm2.HandleNull, plain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  completing  hash sequence %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("digest %s\n", hex.EncodeToString(digest))
	}
}

//  ***********************************************************************
// modified from from go-tpm/tpm2/tpm2.go
// 	CmdHmacStart                  tpmutil.Command = 0x0000015B

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

func HmacStart(rw io.ReadWriter, sequenceAuth string, handle tpmutil.Handle, hashAlg tpm2.Algorithm) (seqHandle tpmutil.Handle, err error) {

	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(sequenceAuth)})
	if err != nil {
		return 0, err
	}
	out, err := tpmutil.Pack(handle)
	if err != nil {
		return 0, err
	}
	Cmd, err := concat(out, auth)
	if err != nil {
		return 0, err
	}

	resp, err := runCommand(rw, tpm2.TagSessions, CmdHmacStart, tpmutil.RawBytes(Cmd), tpmutil.U16Bytes(sequenceAuth), hashAlg)
	if err != nil {
		return 0, err
	}
	var rhandle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &rhandle)
	return rhandle, err
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

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
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
