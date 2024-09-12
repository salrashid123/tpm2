## Importing External HMAC and performing HMAC Signatures

Simple procedure to import an HMAC key into a TPM and signing some data with it.

https://github.com/google/go-tpm/issues/249


### Openssl

```bash
echo -n "change this password to a secret" | xxd -p -c 100
  6368616e676520746869732070617373776f726420746f206120736563726574

echo -n foo > data.in

# openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
       HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```
