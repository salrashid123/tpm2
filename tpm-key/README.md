
### ASN1 format for TPM keys


Verify TPM RSA files using [github.com/foxboron/go-tpm-keyfiles](https://github.com/Foxboron/go-tpm-keyfiles).


This allows for a compact and standard asn.1 format described in https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html openssl honors.

---

### RSA


the code below will 

- create a primary, 
- then an rsa key
- write the keyfile to disk, 
- evit to persistenthandle
- generate a test signature, 
- reread the key from disk, 
- then make another signature.

once all that is done, you can use openssl tss engine to sign and arrive at the same signature 

```bash
$ openssl version
OpenSSL 1.1.1w  11 Sep 2023

$ openssl engine -t -c tpm2tss
(tpm2tss) TPM2-TSS engine for OpenSSL
 [RSA, RAND]
     [ available ]

$ tpm2_evictcontrol --hierarchy=o -c 0x81000000

$ go run main.go --datatosign="foo" --out=private.pem --pcrbank=23 --persistenthandle=0x81000000

2024/05/23 15:08:34 ======= Init  ========
2024/05/23 15:08:34 ======= createPrimary ========
2024/05/23 15:08:35 primaryKey Name 000bdb4455d08239b1b80ffc9cb161b45a1c675a41fd4fb1eacc8f7167b4b730a3d2
2024/05/23 15:08:35 primaryKey handle Value 1073741825
2024/05/23 15:08:35 ======= create key with PCRpolicy ========
2024/05/23 15:08:35 rsa Key PEM: 
-----BEGIN TSS2 PRIVATE KEY-----
MIICNQYGZ4EFCgEDoAMBAf8CBQCBAAAABIIBOgE4AAEACwAEAHIAIDyHpLP7hevu
pYxfs2rCLT8oDOwnqfbdD6I76c5WDe7IABAAFAALCAAAAAAAAQD7Nkd+5XL0nHq5
9Zm4b/H8V2AF0zvyS8pUB2KxzKFPJ5vaqw/6fm9WU+gbRGkgi99gpuR07IqXXOnm
mcpV3aaaZXzYvfmXj+nFoMK86hplCdBArDxtSKuvooh4raMZAvh1e8TYemNFz0l9
ww3GX7adz5vZ+A+nnzYjYdAideUccUv5DuNYpL73YVq/pq6xoAXOQDNmEh7VOjdb
YlSwThfJ5vKfW8/33U4mmfIB/ql0Pgdf5RnA3RGAL5N/4Xwo85IP5JvjJgPK06ur
Y59lzt9XJW6+oOjUjsgClyFdDXGy7TK8/He+DLyjVBpcPs3Zdcl5oVFVSP9xXoX5
d5CWWDO5BIHgAN4AIMHIZX0/rf+U5LKtkaDD/+ALkjI23mcWZYNmXjbK8wzjABC2
bCP4yTDdYn/x3mWLB9aC4lSyEcMz3la7i2Vv9K+Noq64FNgm7wOWJ/Vg+LCMj3wZ
atLaQt8Ks6BxrfbdjiBeevi/AZMzLF6T1lt0w5sbAId7xM2XgefxSCF1mDXFQytV
YBiHpTIYgXJZMFj9RFf01/FxTgnnIpP4pLV9mKwxhmFncZNY3Lgv6T7a/P/nb1+2
PGDV8fTr178M8Gj55M9xh+cHP+3gdLoFcTLlzqJRK6oUQ6RZFwVw4Rg=
-----END TSS2 PRIVATE KEY-----

2024/05/23 15:08:35 ======= generate test signature with RSA key ========
2024/05/23 15:08:35 signature: 8711e1dee83c5236b462f8995ad539fa279f185121ce3ebcf18196cee5978a7a88c05e33d09411f2ad9193a45be1469bed2ea0a070b59b2a53063f5e40749fa6805bd470501f55053d3b51bdc99ca46b155b0c537816bc40dde06e6a4bd30c8148975aea19eddebb0a5932e3ca5007050d0008f49302b067b0d18970c743ef4343ab9f7db5aa1313b38fc7258c4cd59803b216b9edf79c38b2854c6fa96079c864d899034857e9ebe2b2d77581a92756652a3515627a9fff0d87558f1fe648b8a286e4fae4e3fd0581c0fc5b70a7a0308bd8f962664ae09923ba0a4a62134604aa906c63ca41350f77f55ea9d08d2e78aa4ac594c685d6cbe73483883325445b
2024/05/23 15:08:35 regenerated primary key name 000bdb4455d08239b1b80ffc9cb161b45a1c675a41fd4fb1eacc8f7167b4b730a3d2
2024/05/23 15:08:35 signature: 8711e1dee83c5236b462f8995ad539fa279f185121ce3ebcf18196cee5978a7a88c05e33d09411f2ad9193a45be1469bed2ea0a070b59b2a53063f5e40749fa6805bd470501f55053d3b51bdc99ca46b155b0c537816bc40dde06e6a4bd30c8148975aea19eddebb0a5932e3ca5007050d0008f49302b067b0d18970c743ef4343ab9f7db5aa1313b38fc7258c4cd59803b216b9edf79c38b2854c6fa96079c864d899034857e9ebe2b2d77581a92756652a3515627a9fff0d87558f1fe648b8a286e4fae4e3fd0581c0fc5b70a7a0308bd8f962664ae09923ba0a4a62134604aa906c63ca41350f77f55ea9d08d2e78aa4ac594c685d6cbe73483883325445b

```

now use openssl

```bash
echo -n "foo" > data.bin

openssl rsa -engine tpm2tss -inform engine -in private.pem -pubout -outform pem -out publickey.pem
openssl dgst -engine tpm2tss -keyform engine -sha256 -sign private.pem -out data.bin.sig data.bin
openssl dgst -sha256 -verify publickey.pem -signature data.bin.sig data.bin

 xxd -p data.bin.sig 
8711e1dee83c5236b462f8995ad539fa279f185121ce3ebcf18196cee597
8a7a88c05e33d09411f2ad9193a45be1469bed2ea0a070b59b2a53063f5e
40749fa6805bd470501f55053d3b51bdc99ca46b155b0c537816bc40dde0
6e6a4bd30c8148975aea19eddebb0a5932e3ca5007050d0008f49302b067
b0d18970c743ef4343ab9f7db5aa1313b38fc7258c4cd59803b216b9edf7
9c38b2854c6fa96079c864d899034857e9ebe2b2d77581a92756652a3515
627a9fff0d87558f1fe648b8a286e4fae4e3fd0581c0fc5b70a7a0308bd8
f962664ae09923ba0a4a62134604aa906c63ca41350f77f55ea9d08d2e78
aa4ac594c685d6cbe73483883325445b
```

note the singature created in go is the same as with openssl (since no pss)

the parse private key is formatted as

```bash
$ openssl asn1parse -inform PEM -in private.pem
    0:d=0  hl=4 l= 565 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=   3 cons: cont [ 0 ]        
   14:d=2  hl=2 l=   1 prim: BOOLEAN           :255
   17:d=1  hl=2 l=   5 prim: INTEGER           :81000000
   24:d=1  hl=4 l= 314 prim: OCTET STRING      [HEX DUMP]:01380001000B0004007200203C87A4B3FB85EBEEA58C5FB36AC22D3F280CEC27A9F6DD0FA23BE9CE560DEEC800100014000B0800000000000100FB36477EE572F49C7AB9F599B86FF1FC576005D33BF24BCA540762B1CCA14F279BDAAB0FFA7E6F5653E81B4469208BDF60A6E474EC8A975CE9E699CA55DDA69A657CD8BDF9978FE9C5A0C2BCEA1A6509D040AC3C6D48ABAFA28878ADA31902F8757BC4D87A6345CF497DC30DC65FB69DCF9BD9F80FA79F362361D02275E51C714BF90EE358A4BEF7615ABFA6AEB1A005CE403366121ED53A375B6254B04E17C9E6F29F5BCFF7DD4E2699F201FEA9743E075FE519C0DD11802F937FE17C28F3920FE49BE32603CAD3ABAB639F65CEDF57256EBEA0E8D48EC80297215D0D71B2ED32BCFC77BE0CBCA3541A5C3ECDD975C979A1515548FF715E85F97790965833B9
  342:d=1  hl=3 l= 224 prim: OCTET STRING      [HEX DUMP]:00DE0020C1C8657D3FADFF94E4B2AD91A0C3FFE00B923236DE67166583665E36CAF30CE30010B66C23F8C930DD627FF1DE658B07D682E254B211C333DE56BB8B656FF4AF8DA2AEB814D826EF039627F560F8B08C8F7C196AD2DA42DF0AB3A071ADF6DD8E205E7AF8BF0193332C5E93D65B74C39B1B00877BC4CD9781E7F14821759835C5432B55601887A532188172593058FD4457F4D7F1714E09E72293F8A4B57D98AC31866167719358DCB82FE93EDAFCFFE76F5FB63C60D5F1F4EBD7BF0CF068F9E4CF7187E7073FEDE074BA057132E5CEA2512BAA1443A459170570E118

```

#### to print the public part of an encrypted file:

```bash
tpm2_print -t TSSPRIVKEY_OBJ private.pem -f pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6ila7sGempkwfThV8Dqj
ZJe2WsYdIw9QF25w/br55NM9fLRjh8c7D+pbJiyfMsJzJKJnWwz+/HWZRxAt7J/+
7rLUVE8B2/VFf4HPO+YDCdKrK20Wo7B9Se7UAUuHsxH/DCqAYvaIFMe4Ntc+3MrY
iuOp69PCd8smR711bgpJZ3FwQ/EzPWZR1XQ3jCAjDs14OndHy9FL7oxj0iBGJ6m5
mOA5aSNEbnTALDrQHLW6Ow6u8bokgXFvbJccUntfJjuv9yCQDSlZR5Mp6Y0xJM83
ISkeW6wqLXrpHC4Uj05UjZpL8wTl2w08kYa67PBxMrn0BnODBi40raUxTbDh8tca
pwIDAQAB
-----END PUBLIC KEY-----
```


---


### Using tpm2genkey to covert  

[https://github.com/salrashid123/tpm2genkey](https://github.com/salrashid123/tpm2genkey)

### Setup using simulator

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
export TPM2OPENSSL_TCTI="swtpm:port=2321"


rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

### create H2 template
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

### rsa

```bash
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_primes:2  -pkeyopt rsa_keygen_pubexp:65537 -out rsakey.pem
openssl rsa -in rsakey.pem -pubout > rsapub.pem

echo -n "foo" > data.bin
openssl dgst -sha256 -binary data.bin > hash.txt
openssl pkeyutl -sign  -pkeyopt rsa_padding_mode:pkcs1    -inkey rsakey.pem -in hash.txt > data.sign
openssl pkeyutl -verify -in hash.txt -sigfile data.sign -inkey rsapub.pem -pubin


tpm2_import -C primary.ctx  -G rsa2048:rsassa:null -g sha256 -i rsakey.pem -u rsa.pub -r rsa.prv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u rsa.pub -r rsa.prv -c rsa.ctx
tpm2_readpublic -c rsa.ctx  -o rsatpmpub.pem -f PEM -Q
cat rsatpmpub.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_sign -c rsa.ctx -g sha256 -o sig.rssa data.bin
tpm2_verifysignature -c rsa.ctx -g sha256 -s sig.rssa -m data.bin
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

# https://github.com/salrashid123/tpm2genkey
go run cmd/main.go  --mode=tpm2pem --public=/tmp/rsa.pub --private=/tmp/rsa.prv --out=/tmp/rsatpm.pem  --tpm-path="127.0.0.1:2321"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
openssl rsa -provider tpm2  -provider default -in rsatpm.pem --text

openssl dgst -binary -sha256 data.bin > hash.txt
openssl pkeyutl  -provider tpm2  -provider default -sign -pkeyopt rsa_padding_mode:pkcs1 -pkeyopt digest:sha256  -inkey rsatpm.pem  -in hash.txt > data.sign
openssl dgst -provider tpm2  -provider default -verify rsatpmpub.pem  -sha256 -signature data.sign data.bin

```

### ecc

```bash
openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 \
          -pkeyopt ec_param_enc:named_curve \
          -out eckey.pem


openssl ec -in eckey.pem -pubout > ecpub.pem

echo -n "foo" > data.bin
openssl dgst -sha256 -binary data.bin > hash.txt
openssl pkeyutl -sign    -inkey eckey.pem -in hash.txt > data.sign
openssl pkeyutl -verify -in hash.txt -sigfile data.sign -inkey ecpub.pem -pubin


tpm2_import -C primary.ctx  -G ecc:ecdsa  -g sha256   -i eckey.pem -u ec.pub -r ec.prv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u ec.pub -r ec.prv -c ec.ctx
tpm2_readpublic -c ec.ctx  -o ectpmpub.pem -f PEM -Q
cat ectpmpub.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_sign -c ec.ctx -g sha256 -o sig.ec data.bin
tpm2_verifysignature -c ec.ctx -g sha256 -s sig.ec -m data.bin
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

# https://github.com/salrashid123/tpm2genkey
go run cmd/main.go  --mode=tpm2pem --public=/tmp/ec.pub --private=/tmp/ec.prv --out=/tmp/ectpm.pem  --tpm-path="127.0.0.1:2321"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
openssl ec -provider tpm2  -provider default -in ectpm.pem --text


openssl dgst -binary -sha256 data.bin > hash.txt
openssl pkeyutl  -provider tpm2  -provider default -sign  -pkeyopt digest:sha256  -inkey ectpm.pem  -in hash.txt > data.sign
openssl dgst -provider tpm2  -provider default -verify ectpmpub.pem  -sha256 -signature data.sign data.bin
```

#### AES

```bash
openssl rand 16 > sym.key
tpm2_import -C primary.ctx -G aes -i sym.key -u aes.pub -r aes.prv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_load -C primary.ctx -u aes.pub -r aes.prv -c aes.ctx  
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
echo "foo" > secret.dat
openssl rand  -out iv.bin 16


tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c aes.ctx -o encrypt.out secret.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c aes.ctx -d -o decrypt.out encrypt.out
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l   


openssl enc -d -aes-128-cfb   -in encrypt.out  -iv `xxd -p iv.bin` -nosalt  -K `xxd -c 256 -p sym.key`

# https://github.com/salrashid123/tpm2genkey
go run cmd/main.go  --mode=tpm2pem --public=/tmp/aes.pub --private=/tmp/aes.prv --out=/tmp/aestpm.pem  --tpm-path="127.0.0.1:2321"

### openssl does not support loading and using AES PEM keys

```

#### HMAC

```bash
echo -n "change this password to a secret"  > hkey.dat

echo -n "change this password to a secret" | xxd -p -c 100
      6368616e676520746869732070617373776f726420746f206120736563726574

echo -n foo > data.in
openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
           HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

tpm2_import -C primary.ctx -G hmac -i hkey.dat -u hmac.pub -r hmac.prv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_load -C primary.ctx -u hmac.pub -r hmac.prv -c hmac.ctx  
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

cat /tmp/data.in | tpm2_hmac -g sha256 -c hmac.ctx | xxd -p -c 256

# https://github.com/salrashid123/tpm2genkey
go run cmd/main.go  --mode=tpm2pem --public=/tmp/hmac.pub --private=/tmp/hmac.prv --out=/tmp/hmactpm.pem  --tpm-path="127.0.0.1:2321"

### openssl does not support loading and using hmac PEM keys
```
