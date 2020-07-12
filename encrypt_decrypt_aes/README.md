### Encrypt/Decrypt with AES key on OWNER handle


```bash
echo "foo" > secret.dat

tpm2_createprimary -C e -g sha1 -G rsa -c primary.ctx

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx

tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c decrypt.ctx

tpm2_encryptdecrypt -Q -c decrypt.ctx -o encrypt.out secret.dat

tpm2_encryptdecrypt -Q -c decrypt.ctx -d -o decrypt.out encrypt.out
```