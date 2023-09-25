
## Resource Manager

Sample flow using the TPM directly vs the in-kernel Resource Manger

- [TCG TSS 2.0 TAB and Resource Manager Specification](https://trustedcomputinggroup.org/wp-content/uploads/TSS_2p0_TAB_ResourceManager_v1p0_r18_04082019_pub.pdf)

### Direct to TPM

```bash
export TPM2TOOLS_TCTI="device:/dev/tpm0"

tpm2_flushcontext  -t -l -s

## this should be empty
tpm2_getcap   handles-transient

tpm2_createprimary -Q  -C o -g sha1 -G rsa -c primary.ctx
tpm2_getcap -T device:/dev/tpm0  handles-transient
        - 0x80000000


tpm2_create -g sha256 -Q -G aes -u key.pub -r key.priv  -C primary.ctx  
tpm2_getcap -T device:/dev/tpm0  handles-transient
        - 0x80000000
        - 0x80000001

tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx
        WARNING:esys:src/tss2-esys/api/Esys_Load.c:324:Esys_Load_Finish() Received TPM Error 
        ERROR:esys:src/tss2-esys/api/Esys_Load.c:112:Esys_Load() Esys Finish ErrorCode (0x00000902) 
        ERROR: Esys_Load(0x902) - tpm:warn(2.0): out of memory for object contexts
        ERROR: Unable to run tpm2_load

## flush the transient handles to make room
tpm2_flushcontext  -t
tpm2_getcap  handles-transient

# now load the chain:
tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

echo "foo" > secret.dat
openssl rand  -out iv.bin 16
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -o cipher.out  secret.dat

tpm2_flushcontext  -t
tpm2_getcap  handles-transient
tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -d  cipher.out
```


### With Resource Manager

```bash
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

tpm2_flushcontext  -t -l -s
tpm2_getcap   handles-transient

tpm2_createprimary -Q -C o -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -Q -G aes -u key.pub -r key.priv  -C primary.ctx  
tpm2_load -Q -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

echo "foo" > secret.dat
openssl rand  -out iv.bin 16
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -o cipher.out  secret.dat
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -d  cipher.out
```