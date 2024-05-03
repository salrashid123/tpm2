### Duplicate an external HMAC Key using go-tpm

This procedure will duplicate an external HMAC key from one TPM to another.

The `tpm2_tools` version of this is at

- [Duplicate an externally loaded HMAC key](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate#duplicate-an-externally-loaded-hmac-key)


You can extend this sample to RSA or AES keys but this one just focuses on HMAC


One overlooked application of transferring HMAC keys is you can use that to access AWS resources once the transfer is complete

- [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac)
- [AWS Process Credentials for Trusted Platform Module (TPM)](https://github.com/salrashid123/aws-tpm-process-credential)


--- 
you need two vms to do all this:

* VM-A:  this VM is the system where you will create a new hmac key and load it to its tpm
* VM-B:  this is the VM where you will transfer the key from VM-A


you'll need golang and optionally tpm2_tools installed on both VMs

---

### VM-B

First create a wrapper public used to encrypt and transfer the hmac key

The output will create the public/private new-parent.  We will need to transfer `new-parent.pub` from VM-B to VM-A

```bash
$ go run vm-b-1/main.go 
    2024/05/03 12:51:17 ======= Init  ========
    2024/05/03 12:51:17 ======= createPrimary ========
    2024/05/03 12:51:17 Name 000b79103edc0581a829f67158b0d9670012bc15357a45d1bf4eaac91ad0237bf542
    2024/05/03 12:51:17 ======= create ========
    2024/05/03 12:51:17 akPub: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA16eFyesgSKzGI5f+VoFr
    H1RKh5X7bdV1GQhCuln53BdL6wRovDaBRlcGZdxmlpLC98P3dFMb3CjQkPUFipn5
    V3BcDMrEXnkmUJPOO3gCX801DPYU0z9qfaqGCCiobW12aabTjemCs6iW8thbbRlS
    1BYBP6Ng1EExsTxx+tjNvaGNTIVRrG1NyBYHDn+51HzNbOVDEOnCbML6uyHcvxnA
    UzE9eufcZWk/k8Gg5g54iYjPa5J3pcmaMaUQQXlQPPQMPSjEEWNyvjvkmYW57NU0
    +UkxR7m1DRf54HSlSZUtQFOwIBTDUmlIofGbbjiROi0/j+OHQjTfF3+dQ+f1yKcL
    lQIDAQAB
    -----END PUBLIC KEY-----

# optionally print the details of the new-parent

$ tpm2_print -t TPMT_PUBLIC new-parent.pub 
    name-alg:
      value: sha256
      raw: 0xb
    attributes:
      value: sensitivedataorigin|userwithauth|noda|restricted|decrypt
      raw: 0x30460
    type:
      value: rsa
      raw: 0x1
    exponent: 65537
    bits: 2048
    scheme:
      value: null
      raw: 0x10
    scheme-halg:
      value: (null)
      raw: 0x0
    sym-alg:
      value: aes
      raw: 0x6
    sym-mode:
      value: cfb
      raw: 0x43
    sym-keybits: 128
    rsa: d7a785c9eb20

```


[ copy `new-parent.pub` to VM-A ]


### VM-A

On the VM-A, the following app will create a parent object and a child an HMAC key.

Once thats done, a duplication process is started which will result in the encrypted data to transfer back:

* `dup.dup`
* `dup.seed`
* `dup.pub`


```bash
$ go run vm-a/main.go 
    2024/05/03 12:55:16 ======= Init  ========
    2024/05/03 12:55:16 ======= createPrimary ========
    2024/05/03 12:55:16 Name 000b9d90663356697a5e00a7116b18cb4f4f14b3cde08c6730437254dac6b5f72685
    2024/05/03 12:55:16 ======= createHMAC ========

$ tpm2_print -t TPMT_PUBLIC dup.pub 
    name-alg:
      value: sha256
      raw: 0xb
    attributes:
      value: userwithauth|sign
      raw: 0x40040
    type:
      value: keyedhash
      raw: 0x8
    algorithm: 
      value: hmac
      raw: 0x5
    hash-alg:
      value: sha256
      raw: 0xb
    keyedhash: 883643743e3a82682eb74e419b70a8a569e91f726b330cecbb8b0aae697626a8
    authorization policy: bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a2
```

[ copy `dup.pub dup.dup dup.seed` to VM-B ]

### VM-B

Load the wrapped hmac key using the parent we created earlier:

Note this app will also persist the loaded hmac key to a persistent handle:

```bash
## first evict any lingering data
$ tpm2_evictcontrol -c 0x81000001

## now run the load, persist the key and run an hmac operation
$ go run vm-b-2/main.go 
    2024/05/03 13:00:37 ======= Init  ========
    2024/05/03 13:00:37 ======= createPrimary ========
    2024/05/03 13:00:38 Name 000b79103edc0581a829f67158b0d9670012bc15357a45d1bf4eaac91ad0237bf542
    2024/05/03 13:00:38 _---- load -----
    2024/05/03 13:00:38 Import
    2024/05/03 13:00:38 calculated hmac:  7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

## you can also verify the hmac using tpm2_tools 
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c 0x81000001 | xxd -p -c 256
   7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```

to validate, calculate the hmac using off the shelf commands:

```bash
export secret="change this password to a secret"
export plain="foo"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo $hexkey
echo -n $plain > data.in
openssl dgst -sha256 -mac hmac -macopt hexkey:$hexkey data.in
  HMAC-SHA2-256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```
