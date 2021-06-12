## Importing External HMAC and performing HMAC Signatures

Simple procedure to import an HMAC key into a TPM and signing some data with it.

SOme notes first:   

* `tpm2_tools` allows you to generate an HMAC and sign but not import [issue #1597](https://github.com/tpm2-software/tpm2-tools/issues/1597)
* `go-tpm` does not support importing or using HMAC [issue #249](https://github.com/google/go-tpm/issues/249)

What this sample does is showing one way to import a key using go-tpm and then using it to sign.


>> see notes at the end!!!


---

Anyway, lets genrate a secret key and do hmac with it using `openssl` as a baseline

### Openssl

```bash
echo -n "change this password to a secret" | xxd -p -c 100
  6368616e676520746869732070617373776f726420746f206120736563726574

echo -n foo > data.in

# openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
       HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```

### tpm2_tools

Now lets use TPMtools to generate a new key on the device and use it to sign ...ofcourse the hmac's will be different since the key is new and on device...

```bash
$ tpm2_createprimary -c primary.ctx
$ tpm2_create -C primary.ctx -G hmac -c hmac.key

# tpm2_readpublic -c hmac.key 
name: 000bc01c463dc371cbfc689722d2e70b2a04af9dc8c21ae8a785cc37f8b3a2f8c454
qualified name: 000b08de97e29b7516ffb5a3ec31cc6f5dab0bef4ac28f0ef24a616300ed74a98b26
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign
  raw: 0x40072
type:
  value: keyedhash
  raw: 0x8
algorithm: 
  value: hmac
  raw: 0x5
hash-alg:
  value: sha256
  raw: 0xb
keyedhash: 62f56b6afb8373087c2f2aa9791bfd3b327dd4f2e5c3003ea9a0acc66f8cac60

$ tpm2_hmac --hex -c hmac.key  data.in
```


```bash
$ tpm2_hmac  --hex  -c 0x81010002 data.in
    7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

# to flush the persistent handle, use

$ tpm2_evictcontrol -c 0x81010002
```


### go-tpm

Now use go-tpm to create an hmac key, then either save the go-tpm handle to a file or to a persistent handle `0x81010002`

if you run the app, you'll see the predictable hash we got with openssl and that key and message:

```bash
# go run main.go --mode=import
# go run main.go --mode=sign
   digest 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

```

---
## NOTES:

Basically this snippet borrows from [tpm2_test.go](https://github.com/google/go-tpm/blob/master/tpm2/test/tpm2_test.go#L1951)

but uses `tpm2.CreateKeyWithSensitive`

```bash
# tpm2_readpublic -c 0x81010002

name: 000b8fb81fa736a1cc6aae780f7ff5d32d6efc3b495ce1854af8aac9dc56dec287ee
qualified name: 000b23eba35005caaacdfa30defedc83a9c4986ed43be8728d544cbb93223d5b8045
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|userwithauth|sign
  raw: 0x40052
type:
  value: keyedhash
  raw: 0x8
algorithm: 
  value: hmac
  raw: 0x5
hash-alg:
  value: sha256
  raw: 0xb
keyedhash: 3d2733a76ef6723e5ddb7e1ab88eab0c5e9b2728606756334cc9639570b26cea

```
