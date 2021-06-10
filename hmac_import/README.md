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
$ go run main.go 
   digest 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```

---
## NOTES:

I'm pretty sure the implementation on how i'm importing the HMAC key isn't correct...the object attributes are not set correctly and the key isn't wrapped with internal/eternal wrapper.

Basically this snippet borrows from [tpm2_test.go](https://github.com/google/go-tpm/blob/master/tpm2/test/tpm2_test.go#L1951)

which clearly state:

```golang
		// https://github.com/google/go-tpm/blob/master/tpm2/test/tpm2_test.go#L1951

		//  The following isn't the right way to import the hmac key.
		//  it should be encrypted per
		// "As this test imports a key without using an inner or outer wrapper, the
		// sensitive data is NOT encrypted. This setup should not actually be used."
		// import should actually use
```

When what i should likely be doing is:

```bash
		//  https://github.com/google/go-tpm/blob/master/tpm2/tpm2.go#L617

		// Import allows a user to import a key created on a different computer
		// or in a different TPM. The publicBlob and privateBlob must always be
		// provided. symSeed should be non-nil iff an "outer wrapper" is used. Both of
		// encryptionKey and sym should be non-nil iff an "inner wrapper" is used.
```

TODO: i think i should use 


```golang
	public := tpm2.Public{
		Type:    tpm2.AlgKeyedHash,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:    tpm2.AlgHMAC,
			Hash:   tpm2.AlgSHA256,
		},
	}

	privInternal, pubArea, _, _, _, err = tpm2.CreateKeyWithSensitive(rwc, parentHandle, pcrSelection, emptyPassword,emptyPassword, public, hmacKeyBytes)
	if err != nil {

		fmt.Fprintf(os.Stderr, "Error failed to create key %v\n", err)
		os.Exit(1)
	}
```

instead.....its just i don't know how to do that yet

At the moment, if you use go-tpm to genreate a key, you'll see the following specs...(note the attributes are not right...)

```bash
# tpm2_readpublic -c 0x81010002
name: 000b754eed8a76fdca5f1a23a96866756bc0bf26f59a9a0e448dd9f6a51df1da77f2
qualified name: 000b43abb3d2468bdd900682d3ab9eab29a61e2dd5415243c1eab63c5c55aecaaca4
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: sensitivedataorigin|userwithauth|sign
  raw: 0x40060
type:
  value: keyedhash
  raw: 0x8
algorithm: 
  value: hmac
  raw: 0x5
hash-alg:
  value: sha256
  raw: 0xb
keyedhash: 25ba9e58026a36c757b2bf67fdb8c4f16982ce92e493220a1f7b02d8c9f2dc1f
```
