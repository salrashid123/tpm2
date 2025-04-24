package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/hashicorp/vault/sdk/helper/kdf"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "tpm-key.pem", "privateKey File")
)

func main() {

	flag.Parse()
	b := []byte("foo")

	key := []byte("my_api_key")
	prf := kdf.HMACSHA256PRF
	prfLen := kdf.HMACSHA256PRFLen

	/// Vault
	out, err := kdf.CounterMode(prf, prfLen, key, b, 256)
	if err != nil {
		panic(err)
	}

	log.Printf("Vault  KDF %s\n", hex.EncodeToString(out))

	//// TPM

	r, err := kdf.CounterMode(TPMHMACSHA256PRF, prfLen, nil, b, 256)
	if err != nil {
		panic(err)
	}

	log.Printf("TPM    KDF %s\n", hex.EncodeToString(r))
}

func TPMHMACSHA256PRF(key []byte, data []byte) ([]byte, error) {
	return TPMHMAC(*tpmPath, *in, data)
}

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

const (
	maxInputBuffer = 1024
)

func TPMHMAC(tpmPath string, pemkey string, data []byte) ([]byte, error) {

	rwc, err := openTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	c, err := os.ReadFile(pemkey)
	if err != nil {
		return nil, err
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		return nil, err
	}

	// specify its parent directly
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: key.Parent,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	hKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	objAuth := &tpm2.TPM2BAuth{
		Buffer: nil,
	}

	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sasCloser()
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: hKey.ObjectHandle,
			Name:   hKey.Name,
			Auth:   sas,
		},
		Auth:    *objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   hKey.Name,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
