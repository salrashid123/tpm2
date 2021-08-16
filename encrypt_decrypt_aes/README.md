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