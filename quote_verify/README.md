
# QUOTE with PCR

Issue a TPM quote with PCR Bank 23:

1. Create EK, AK
```bash
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_readpublic -c ek.ctx  -o ek.pem -f PEM

$ tpm2_print -t TPMS_CONTEXT ek.ctx
  version: 1
  hierarchy: endorsement
  handle: 0x80000000 (2147483648)
  sequence: 66
  contextBlob: 
    size: 1614

$ tpm2_createak -C ek.ctx -c ak.ctx -u ak.pem -n ak.name -f PEM 
      loaded-key:
        name: 000bc02d0ad924f83ea4b7592d55ae861ceaee0b833c8e6dac45b4a93825700b43cf
```

2. Read and mutate PCR value 23

If this an uninitialized bank, you'll see 000's, whatever the value is, apply it to the `tpm2_extend` function.  If 00's,
```bash
$ tpm2_pcrread sha256:23
    sha256:
      23: 0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
```


3. Save the value of PCR bank 23 to a file
```
$ tpm2_pcrread sha256:23 -o pcr_val.out
sha256:
  23: 0x536D98837F2DD165A55D5EEAE91485954472D56F246DF256BF3CAE19352A123C
```


4. Issue a quote using AK, pcr value and a nonce (`666f6f`)

The nonce is `hex(foo)-->666f6f`

```
$ tpm2_quote  -c ak.ctx -l sha256:23 -m quote_message.bin -s quote.signed -o pcr.out -q 666f6f
    quoted: ff5443....
    signature:
      alg: rsassa
      sig: 81b0a6e12dabe57ffe...
    pcrs:
      sha256:
        23: 0x536D98837F2DD165A55D5EEAE91485954472D56F246DF256BF3CAE19352A123C
    calcDigest: faa83fc32bf1f4dae12b9c8a4595d93b3d56cb997569df
```

5. Verify the quote using AK, the value for the nonce you expect
```
$ tpm2_checkquote -u ak.pem -m quote_message.bin -s quote.signed -f pcr.out  -g sha256 -q 666f6f
    pcrs:
      sha256:
        23: 0x536D98837F2DD165A55D5EEAE91485954472D56F246DF256BF3CAE19352A123C
```

Once the quote_message is verified, you can also use `tpm2_print` to view full details of the object.  Note, pcr bank of sha256 is selected and `pcrDigest` is a digest of the PCR's requested

```
$ tpm2_print -t TPMS_ATTEST quote_message.bin
    magic: ff544347
    type: 8018
    qualifiedSigner: 000beea12329ba64aee0cff68a9f9dec7b8d6a91706eed7295678ea2094e009d5997
    extraData: 666f6f
    clockInfo:
      clock: 630415182
      resetCount: 2
      restartCount: 0
      safe: 1
    firmwareVersion: 2016051100162800
    attested:
      quote:
        pcrSelect:
          count: 1
          pcrSelections:
            0:
              hash: 11 (sha256)
              sizeofSelect: 3
              pcrSelect: 000080
        pcrDigest: faa83fc32bf1f4dae12b9c8a4595d93b3d56cb997569df15c219f3b2377723f4
```

Use an incorrect PCR value (eg, `pcr_old.out` here holds `pcr23=0x536D98837F2DD165A55D5EEAE91485954472D56F246DF256BF3CAE19352A123C` )

```
$ tpm2_checkquote -u ak.pem -m quote_message.bin -s quote.signed -f pcr_old.out  -g sha256 -q 666f6f
    pcrs:
      sha256:
        23: 0x536D98837F2DD165A55D5EEAE91485954472D56F246DF256BF3CAE19352A123C
    ERROR: FATAL ERROR: PCR values failed to match quote's digest!
    ERROR: Error validating PCR composite against signed message
    ERROR: Verify signature failed!
    ERROR: Unable to run tpm2_checkquote
```

# With Openssl

```
# tpm2_quote  -c ak.ctx -l sha256:23 -m quote_message.bin -s quote.signed  -o pcr.out -q 666f6f  -f plain
    quoted: ff54434780180022000bf12156051ef79d1c59b72989e00b04ce65fcc2f9b049b06153507646d0ed3ca20003666f6f000000001edb74ad000000020000000001201605110016280000000001000b030000800020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9
    signature:
      alg: rsassa
      sig: 2e0f46bb7dba9633d327e8b16009edea2de0196e37e3dd631714a157a6b7e0ec1689f5166e4b58959708c60de41d6117005a4b5be57dd948214804db7921d2bc832d57eb72d383fecda4ace7c91a78c61b25a9c91c552ad3684e86b20fce3eb046307173ca77538b61ceb57394c00a915ea826c86dfa0a53e5176f164b488e64c3f38f6d8a661875e399470504d0d44315b2ed2c7fd8d3a28c4b062a2c43de4dcea27bf982d3dbfa52eeb111344fe9455f8667d9f7851d5a141c7c56e9c1885d4ddd1557f7dff5ae1a6c6b9dec15125df7fd53f43409f8d5da461bf3dd2b5526e2ada2244f998e5c5eac10afbcfef511883bcab2f3fa8d0ce59ebee06d06b4ba
    pcrs:
      sha256:
        23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
    calcDigest: e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9
```

```
$ openssl dgst -sha256 -verify ak.pem -signature quote.signed  quote_message.bin
Verified OK
```


---


```
#  go run main.go  --logtostderr=1 -v 5
I1029 04:07:21.922679   14775 main.go:33] ======= Init  ========
I1029 04:07:21.934420   14775 main.go:60] 0 handles flushed
I1029 04:07:21.935881   14775 main.go:71] PCR 0xc00001a3c8 Value 9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30 
I1029 04:07:21.941757   14775 main.go:82] quotebytes Data /1RDR4AYACIAC+6hIym6ZK7gz/aKn53se41qkXBu7XKVZ46iCU4AnVmXAA1tZWV0IG1lIGF0Li4uAAAAACW9ivkAAAACAAAAAAEgFgURABYoAAAAAAEACwMAAIAAILrrP1/09VuidJqUmTz5iDMxmWRg1EvU8UWibaQs+kNx
I1029 04:07:21.941892   14775 main.go:83] Signature data:  gmxBOvO4l4eOSkg6ckKHgMOqA9tSuH+BNvNZhE8/F2qbH0LQbSPCMvIGixhom6Q6CLT5rUtGYFD0dLwXtHp+uujalNW0MDY2IQlK6qkSP8zHF8c+wtzujYOxfeyqRTMFDrsyB+gyZ07AnEOUSbi1Q9gm32eNhyk5dta03jrbhgaSQSl0AdW60gxertLgnapaaoPWHuk2K/S6D0uoCQGNhmq6Z1e6QbHkVU4YQHUP6CuMrpVw1QQ0lVlolY6sNImZ4APd1LjzlaBtgsHdoFpSgH5Jus1PeZRq4iDmJDrBKycFNmVYb6VykZDQwloNmoiX4P6ZVZ4CUveqYPiOwt2VRw

```