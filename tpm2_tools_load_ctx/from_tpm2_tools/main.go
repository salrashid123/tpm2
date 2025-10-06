package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"

	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
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

func main() {
	flag.Parse()

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	var ctx tpm2.TPMSContext
	primaryCtx, err := os.ReadFile("key.ctx")
	if err != nil {
		panic(err)
	}

	reader := bytes.NewReader(primaryCtx)

	var magic uint32
	if err := binary.Read(reader, binary.BigEndian, &magic); err != nil {
		fmt.Printf("Failed to read magic: %v", err)
	}
	fmt.Printf("header:  %x\n", magic)

	var ver uint32
	if err := binary.Read(reader, binary.BigEndian, &ver); err != nil {
		fmt.Printf("Failed to read verison: %v", err)
	}
	fmt.Printf("version:  %x\n", ver)

	if err := binary.Read(reader, binary.BigEndian, &ctx.Hierarchy); err != nil {
		fmt.Printf("Failed to read hierarchy: %v", err)
	}
	fmt.Printf("Hierarchy: %x\n", ctx.Hierarchy)

	if err := binary.Read(reader, binary.BigEndian, &ctx.SavedHandle); err != nil {
		fmt.Printf("Failed to read savehandle: %v", err)
	}
	fmt.Printf("SavedHandle: %x\n", ctx.SavedHandle.HandleValue())

	if err := binary.Read(reader, binary.BigEndian, &ctx.Sequence); err != nil {
		fmt.Printf("Failed read sequence %v", err)
	}
	fmt.Printf("Sequence: %d\n", ctx.Sequence)

	var sizecm uint16
	if err := binary.Read(reader, binary.BigEndian, &sizecm); err != nil {
		fmt.Printf("Failed to size: %v", err)
		return
	}

	contextDataMeta := make([]byte, sizecm)
	if err := binary.Read(reader, binary.BigEndian, contextDataMeta); err != nil {
		fmt.Printf("Failed to read context data buffer: %v", err)
		return
	}
	fmt.Printf("context+metadata: %s\n", hex.EncodeToString(contextDataMeta))

	// // UINT32 always zero (/* Must always be zero */ 10.13 Esys_ContextSave Commands https://trustedcomputinggroup.org/wp-content/uploads/TSS_TSS-2.0-Enhanced-System-API_V0.9_R03_Public-Review-1.pdf )
	// so discard it
	readerr := bytes.NewReader(contextDataMeta)
	io.CopyN(io.Discard, readerr, 4)

	// now read the aize
	var sizem uint16
	if err := binary.Read(readerr, binary.BigEndian, &sizem); err != nil {
		fmt.Printf("Failed to parse size: %v", err)
		return
	}
	fmt.Printf("Size of context: %d\n", sizem)

	contextData := make([]byte, sizem)
	if err := binary.Read(readerr, binary.BigEndian, contextData); err != nil {
		fmt.Printf("Failed to read context data buffer: %v", err)
		return
	}
	fmt.Printf("context: %s\n", hex.EncodeToString(contextData))

	var sizeOprand uint16
	if err := binary.Read(readerr, binary.BigEndian, &sizeOprand); err != nil {
		fmt.Printf("Failed to parse size: %v", err)
		return
	}
	fmt.Printf("     oprand: %d\n", sizeOprand)

	var handle uint32
	if err := binary.Read(readerr, binary.BigEndian, &handle); err != nil {
		fmt.Printf("Failed to parse size: %v", err)
		return
	}
	fmt.Printf("     handle %x\n", handle)

	var sizeLen uint16
	if err := binary.Read(readerr, binary.BigEndian, &sizeLen); err != nil {
		fmt.Printf("Failed to parse size: %v", err)
		return
	}

	objname := make([]byte, sizeLen)
	if err := binary.Read(readerr, binary.BigEndian, objname); err != nil {
		fmt.Printf("Failed to name buffer: %v", err)
		return
	}
	fmt.Printf("     name: %s\n", hex.EncodeToString(objname))

	selector := make([]byte, 4)
	if err := binary.Read(readerr, binary.BigEndian, selector); err != nil {
		fmt.Printf("Failed to read selctor: %v", err)
		return
	}
	fmt.Printf("     selector: %s\n", hex.EncodeToString(selector))

	public := make([]byte, readerr.Len())
	if err := binary.Read(readerr, binary.BigEndian, public); err != nil {
		fmt.Printf("Failed to read context data buffer: %v", err)
		return
	}
	fmt.Printf("     public: %s\n", hex.EncodeToString(public))
	rspCL, err := tpm2.ContextLoad{
		Context: tpm2.TPMSContext{
			Sequence:    ctx.Sequence,
			SavedHandle: ctx.SavedHandle,
			Hierarchy:   ctx.Hierarchy,
			ContextBlob: tpm2.TPM2BContextData{
				Buffer: contextData,
			},
		},
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("ContextLoad failed: %v", err)
		return
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rspCL.LoadedHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	ra, err := tpm2.ReadPublic{
		ObjectHandle: rspCL.LoadedHandle,
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't create object TPM %q: %v", *tpmPath, err)
		return
	}
	fmt.Printf("Recalled Name %s\n", hex.EncodeToString(ra.Name.Buffer))

	data := []byte("foooo")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		fmt.Printf("can't read rsa details %q: %v", *tpmPath, err)
		return
	}

	keyAuth := tpm2.AuthHandle{
		Handle: rspCL.LoadedHandle,
		Name:   ra.Name,
		Auth:   tpm2.PasswordAuth([]byte("")),
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, false)

	if err != nil {
		fmt.Printf("EncryptSymmetric failed: %s", err)
		return
	}
	fmt.Printf("IV: %s", hex.EncodeToString(iv))
	fmt.Printf("Encrypted %s", hex.EncodeToString(encrypted))

	decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, encrypted, true)
	if err != nil {
		fmt.Printf("EncryptSymmetric failed: %s", err)
		return
	}

	fmt.Printf("Decrypted %s", string(decrypted))
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
