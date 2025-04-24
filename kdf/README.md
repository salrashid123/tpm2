Snippet which uses `NIST SP 800-108` KDF with Countermode
basically, this is an adaptation of [github.com/hashicorp/vault/sdk/helper/kdf#CounterMode](https://pkg.go.dev/github.com/hashicorp/vault/sdk/helper/kdf#CounterMode).

but with the HMAC operation using the TPM.

---

the sample below uses a `swtpm` where the hmac key is saved as a PEM encoded file.
 
First embed the key:

```bash
sudo swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"

export secret="my_api_key"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo $hexkey

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2 import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx
tpm2_encodeobject -C primary.ctx -u hmac.pub -r hmac.priv -o tpm-key.pem
```

then if you run, a new key is derived by both the TPM and the default vault library of the same.

the expected result is the same

```bash
$ go run main.go
2025/04/23 15:52:39 TPM    KDF 8ee68b83a24249fd9dcd162921c3f5486f591620a871bedf9efce044d5e74734
2025/04/23 15:52:39 Vault  KDF 8ee68b83a24249fd9dcd162921c3f5486f591620a871bedf9efce044d5e74734
```

