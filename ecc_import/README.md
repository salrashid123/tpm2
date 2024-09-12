# Importing an external key and load it ot the TPM


### create ecc key 

```bash
openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 \
      -pkeyopt ec_param_enc:named_curve \
      -out private.pem

```

## using tpm2_tools

```bash
	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
```


### create 

```bash
$ go run importExternalRSA.go --mode=create --keyPub key.pub --keyPriv=key.priv --pemFile=private.pem --handle=0x81010002


```




---

```bash
# more private.pem 
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaAe9jz/XJMwpsgTP
KmmS/0rWvPkInMjhXQoRgvScQuWhRANCAAQcnaAC7weNrICA5jWrH0MLiAgAWpk+
lzTjE2jX+NJLIhDZSVkGfErt0kBk4k++ckWN8w5HpD8RybW690+IPi9h
-----END PRIVATE KEY-----
```