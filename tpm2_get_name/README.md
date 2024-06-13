# Get EK "Name"

Sample program that uses the PEM format of a Key to get its "name" from the RSA Public key


```bash
$ go run main.go
Name 000b7d5ae2283593ce63281bd4a5b681b50ceff54a49e17ee6e40bc8e82f47967d55
PEM
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnMDg8UTDAfb8+wdYQFbz
M3XkvBDBY30G77JlIuYH4FElqNUFruIrdGCW21jqCwauFJC/He+fjYJE7giy7TGi
fr6yLn+f7fIeVYKB5bZofaO/8uRdRD4GsG8+Y3ywQdEsQuZ23bmAZHBZjfHdWGi8
DYWTjIWfSaSRkKKLovaaV0vdLR+3AbVcswiTFYtxMjkHn/ss4CkBPGIzqyqFchFV
I/DAhXn/xTtKPZYxLNelbvLH1hYoHEIyHfvw5nf+2CxINdVBWx5S2V6nFuzLXPYC
WGtoAkVO7oM+So41pIy/C8iOix6NtfiNyOy7LfXzkvajiEX/Gn6c6wXiHNhayFLv
2QIDAQAB
-----END PUBLIC KEY-----

Name 000b7d5ae2283593ce63281bd4a5b681b50ceff54a49e17ee6e40bc8e82f47967d55
```

if using swtpm:

```bash
$ rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

 export TPM2TOOLS_TCTI="swtpm:port=2321"

```

