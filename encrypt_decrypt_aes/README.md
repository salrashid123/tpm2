### Encrypt/Decrypt with AES key on OWNER handle

optionally seed the "unique" bit
https://github.com/tpm2-software/tpm2-tools/issues/2378


```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

printf '\x00\x01' > ud.1
dd if=/dev/random bs=256 count=1 of=ud.2
cat ud.1 ud.2 > unique.dat

tpm2_createprimary -C o -g sha1 -G rsa -c primary.ctx -u unique.dat

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx

tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx

tpm2_encryptdecrypt -Q --iv iv.bin -c decrypt.ctx -o encrypt.out secret.dat

tpm2_encryptdecrypt -Q --iv iv.bin -c decrypt.ctx -d -o decrypt.out encrypt.out
```


To use the "Direct" go-tpm api, i used a simulator here:


```bash
go run main.go --handle=0x81008001 --tpm-path="127.0.0.1:2321"
```


Note, the go example below uses the "direct" api which does not yet officially support tpm2_encryptdecrypt2.  I'll file a PR with the changes to go-tpm to include

```golang
// structures.go
// TPM2BIV represents a TPM2B_IV.
// See definition in Part 2: Structures, section 10.4.11.
type TPM2BIV TPM2BData


// tpm2.go
// EncryptDecrypt2 is the input to TPM2_EncryptDecrypt2
type EncryptDecrypt2 struct {
	// reference to public portion of symmetric key to use for encryption
	KeyHandle handle `gotpm:"handle,auth"`
	Message   TPM2BMaxBuffer
	Decrypt   TPMIYesNo
	Mode      TPMIAlgSymMode `gotpm:"nullable"`
	IV        TPM2BIV
}

// Command implements the Command interface.
func (EncryptDecrypt2) Command() TPMCC { return TPMCCEncryptDecrypt2 }

// Execute executes the command and returns the response.
func (cmd EncryptDecrypt2) Execute(t transport.TPM, s ...Session) (*EncryptDecrypt2Response, error) {
	var rsp EncryptDecrypt2Response
	err := execute[EncryptDecrypt2Response](t, cmd, &rsp, s...)
	if err != nil {
		return nil, err
	}
	return &rsp, nil
}

type EncryptDecrypt2Response struct {
	OutData TPM2BMaxBuffer
	IV      TPM2BIV
}
```