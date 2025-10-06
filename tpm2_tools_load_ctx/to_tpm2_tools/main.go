package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
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
)

const (
	magic   = "badcc0de" // static const UINT32 MAGIC = 0xBADCC0DE;
	version = "00000001" // #define CONTEXT_VERSION 1
)

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

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't create primary %v", err)
		return
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	c, err := os.ReadFile("key.pem")
	if err != nil {
		fmt.Printf("can't load keys %q: %v", *tpmPath, err)
		return
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		fmt.Printf("can't decode keys %q: %v", *tpmPath, err)
		return
	}

	rsaKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't load  key : %v", err)
		return
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	s, err := tpm2.ContextSave(tpm2.ContextSave{
		SaveHandle: rsaKey.ObjectHandle,
	}).Execute(rwr)
	if err != nil {
		fmt.Printf("can't load  hmacKey : %v", err)
		return
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: s.Context.SavedHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	fmt.Printf("Hierarchy: %08X\n", s.Context.Hierarchy.HandleValue())
	fmt.Printf("SavedHandle %08X\n", s.Context.SavedHandle.HandleValue())
	fmt.Printf("Sequence: %d\n", s.Context.Sequence)

	fmt.Printf("ContextBLob Length: %v\n", len(s.Context.ContextBlob.Buffer))
	fmt.Printf("ContextBLob: %v\n", hex.EncodeToString(s.Context.ContextBlob.Buffer))

	name := rsaKey.Name.Buffer
	fmt.Printf("Name: %s\n", hex.EncodeToString(name))

	public := key.Pubkey.Bytes()

	fmt.Printf("Public : %s\n", hex.EncodeToString(public))

	/// ********************************************************

	// first create the header and the savecontext  hierarchy, savehandle and sequence
	buf := new(bytes.Buffer)

	// magic
	magicBytes, err := hex.DecodeString(magic)
	if err != nil {
		fmt.Printf("can't load  hmacKey : %v", err)
		return
	}
	buf.Write(magicBytes)

	// version
	var version uint32 = 1
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, version)
	buf.Write(versionBytes)

	// hierarchy
	var hiearchy uint32 = primaryKey.CreationTicket.Hierarchy.HandleValue() // tpm2.TPMRHOwner.HandleValue() // 0x40000001
	hierarchyBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(hierarchyBytes, hiearchy)
	buf.Write(hierarchyBytes)

	// savehandle
	err = binary.Write(buf, binary.BigEndian, s.Context.SavedHandle.HandleValue())
	if err != nil {
		log.Fatalf("Failed to write binary data: %v", err)
	}

	// sequence
	var sequence uint64 = s.Context.Sequence
	sequenceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sequenceBytes, sequence)
	buf.Write(sequenceBytes)

	/// now create the bufer for the context+metadata

	bufferContextMetadata := new(bytes.Buffer)

	// zero prefix
	var zeroPrefix uint16 = 0
	bufferZero := make([]byte, 2)
	binary.BigEndian.PutUint16(bufferZero, zeroPrefix)
	bufferContextMetadata.Write(bufferZero)

	// context blob length + contextblob bytes
	var contextBlobLength uint32 = uint32(len(s.Context.ContextBlob.Buffer))
	contextBlobLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(contextBlobLengthBytes, contextBlobLength)
	bufferContextMetadata.Write(contextBlobLengthBytes)

	bufferContextMetadata.Write(s.Context.ContextBlob.Buffer)

	// oprand size
	var oprand uint16 = 0
	oprandBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(oprandBytes, oprand)
	bufferContextMetadata.Write(oprandBytes)

	// handle
	var handleValue uint32 = rsaKey.ObjectHandle.HandleValue() // 0x80000001
	handleValueBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(handleValueBytes, handleValue)
	bufferContextMetadata.Write(handleValueBytes)

	// encode the namelength and name
	var nameLength uint16 = uint16(len(name))
	nameLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLengthBytes, nameLength)
	bufferContextMetadata.Write(nameLengthBytes)

	bufferContextMetadata.Write(name)

	// selector
	var selector uint32 = 1
	selectorBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(selectorBytes, selector)
	bufferContextMetadata.Write(selectorBytes)

	// prblic length and bytes
	var publen uint16 = uint16(len(public))
	publicBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(publicBytes, publen)
	bufferContextMetadata.Write(publicBytes)

	bufferContextMetadata.Write(public)

	// now get the lenth of all the metadata
	var metadata uint16 = uint16(len(bufferContextMetadata.Bytes()))
	metadataByteLength := make([]byte, 2)
	binary.BigEndian.PutUint16(metadataByteLength, metadata)

	buf.Write(metadataByteLength)

	buf.Write(bufferContextMetadata.Bytes())

	fmt.Printf("final bytes to write    %s\n", hex.EncodeToString(buf.Bytes()))

	outputFileName := "output.ctx"

	err = os.WriteFile(outputFileName, buf.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

}
