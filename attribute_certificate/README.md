
### Create Attribute Certificate from EKCert


start swtpm

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
   swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
   swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

```


extract the ekcert
```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"

tpm2_getekcertificate -X -o ECcert.bin
openssl x509 -in ECcert.bin -inform DER -noout -text
openssl x509 -inform der -in ECcert.bin -out ECcert.pem

```