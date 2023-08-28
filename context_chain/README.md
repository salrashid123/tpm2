## Chained Keys

Snippet which creates a primary, then a child, then a grandchild.

Use the leaf key to encrypt/decrypt

ref [TPM-JS Cryptographic Keys](https://google.github.io/tpm-js/#pg_keys)


```bash
go run main.go --mode=create

[reboot]

go run main.go --mode=load
```


```bash
# create root
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx 

# create child
tpm2_create -g sha256 -u key_2.pub -r key_2.priv -C primary.ctx  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt"
tpm2_load -C primary.ctx -u key_2.pub -r key_2.priv  -c key_2.ctx


# create a grandchild (use key_2 as the immediate parent)
tpm2_create -g sha256 -G aes -u key_3.pub -r key_3.priv -C key_2.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"
tpm2_load -C key_2.ctx -u key_3.pub -r key_3.priv -c key_3.ctx


# encrypt/decrypt
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_encryptdecrypt  --iv iv.bin -c key_3.ctx -o encrypt.out secret.dat
tpm2_encryptdecrypt  --iv iv.bin -c key_3.ctx -d  encrypt.out 
```


---

#### verify chain after reboot

```bash
### attempt to load grandchild directly without loading child
##### this will give an error as expected

tpm2_load -C key_2.ctx -u key_3.pub -r key_3.priv -c key_3.ctx
        WARNING:esys:src/tss2-esys/api/Esys_ContextLoad.c:279:Esys_ContextLoad_Finish() Received TPM Error 
        ERROR:esys:src/tss2-esys/api/Esys_ContextLoad.c:93:Esys_ContextLoad() Esys Finish ErrorCode (0x000001df) 
        ERROR: Esys_ContextLoad(0x1DF) - tpm:parameter(1):integrity check failed
        ERROR: Incorrect handle value, got: "key_2.ctx", expected expected [o|p|e|n|l] or a handle number
        ERROR: Unable to read PEM from provided BIO/file
        ERROR: Unable to fetch public/private portions of TSS PRIVKEY
        ERROR: Cannot make sense of object context "key_2.ctx"


### now try to load the child
##### this will give an error as expected because we haven't loaded the parent context
tpm2_load -C primary.ctx -u key_2.pub -r key_2.priv  -c key_2.ctx
        WARNING:esys:src/tss2-esys/api/Esys_ContextLoad.c:279:Esys_ContextLoad_Finish() Received TPM Error 
        ERROR:esys:src/tss2-esys/api/Esys_ContextLoad.c:93:Esys_ContextLoad() Esys Finish ErrorCode (0x000001df) 
        ERROR: Esys_ContextLoad(0x1DF) - tpm:parameter(1):integrity check failed
        ERROR: Incorrect handle value, got: "primary.ctx", expected expected [o|p|e|n|l] or a handle number
        ERROR: Unable to read PEM from provided BIO/file
        ERROR: Unable to fetch public/private portions of TSS PRIVKEY
        ERROR: Cannot make sense of object context "primary.ctx"
        ERROR: Unable to run tpm2_load

### regenerate the parent
##### we will actually get the same parent key every time since w'ere deriving from a non null hierarchy
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

### now load the children
tpm2_load -C primary.ctx -u key_2.pub -r key_2.priv  -c key_2.ctx

tpm2_load -C key_2.ctx -u key_3.pub -r key_3.priv -c key_3.ctx

### now decrypt 
tpm2_encryptdecrypt  --iv iv.bin -c key_3.ctx -d  encrypt.out 
```