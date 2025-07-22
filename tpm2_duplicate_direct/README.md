### Duplicate and Transfer without local TPM on source


THis sample basically transfers an RSA key from your laptop to a remote `TPM-B`.

The difference with this sample is the duplicate is generated locally using `TPM-B's` but the local laptop does not use its tpm to generate the duplicating key.

Instead, the duplicate is generated localy without a TPM and by running the same steps as the TPM would be doing.


to use:

start a swtpm to simulate `TPM-B`

```bash
/usr/share/swtpm/swtpm-create-user-config-files
rm -rf myvtpm && mkdir myvtpm  && \
   swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert && \
   swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5


### extract its ekpub
export TPM2TOOLS_TCTI="swtpm:port=2321"

tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o ek.pem -f PEM -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

### create an RSA key

```bash
openssl genrsa -out /tmp/key.pem 2048
openssl rsa -in /tmp/key.pem -out key_rsa.pem -traditional
```

### create a duplicate

```bash
go run main.go
```

