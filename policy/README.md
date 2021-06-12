## Using Policies to AES Encrypt/Decrypt

## No Policy

```bash
echo "foo" > secret.dat


tpm2_createprimary -C e -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx
tpm2_encryptdecrypt -Q -c decrypt.ctx -o encrypt.out secret.dat
tpm2_encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out
```

## Password Policy

```bash
echo "foo" > secret.dat

tpm2_startauthsession -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C e -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat -p testpswd
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx

tpm2_encryptdecrypt -Q -c decrypt.ctx -o encrypt.out -p testpswd  secret.dat
tpm2_encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out -p testpswd encrypt.out
```
 

## PCR Policy

```bash

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C e -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx

echo "foo" > secret.dat

tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_encryptdecrypt -Q -c decrypt.ctx -o encrypt.out   secret.dat  -p"pcr:sha256:23=pcr23_val.bin"
tpm2_encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out  -p"pcr:sha256:23=pcr23_val.bin"


tpm2_pcrread sha256:23
tpm2_pcrextend  23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23
    sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
tpm2_pcrextend  23:sha256=0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```


### Saving a policy to NV

https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policyauthorizenv.1.md