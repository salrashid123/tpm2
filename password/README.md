### Encrypt/Decrypt with AES and auth passwords

auth password set on both the parent and key



```bash
## using swtpm:
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
export TPM2TOOLS_TCTI="swtpm:port=2321"


echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx -p primarypwd
tpm2_flushcontext -t
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx  -p keypwd -P primarypwd
tpm2_flushcontext -t
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx -P primarypwd
tpm2_flushcontext -t

tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -o cipher.out -p bar  secret.dat -p keypwd
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -d -o plain.out -p bar cipher.out -p keypwd
```


note, the go-tpm example uses encryptdecrypt2 which isn't supported as of 6/18/24. i have it working locally and will file a PR against go-tpm shortly