
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

## Quote-verify using go-tpm-tools

The following code *ONLY* support RSA256 

#### Create Ek,AK (one time)

```bash
# go run main.go --mode createKey --pcr 23 --logtostderr=1 -v 5
I0319 11:55:53.731509   29733 main.go:127] ======= Init CreateKeys ========
I0319 11:55:53.749752   29733 main.go:149] Handle 0x80000000 flushed
I0319 11:55:53.749774   29733 main.go:154] 1 handles flushed
I0319 11:55:53.751422   29733 main.go:161] PCR 23 Value f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b 
I0319 11:55:53.751444   29733 main.go:166] ======= createPrimary ========
I0319 11:55:53.884118   29733 main.go:198] ekPub Name: 000bae2e4d564b3592c3781c6e774ffb8ca680f9d103b80c1ab1aa058e5f2b1412f7
I0319 11:55:53.884143   29733 main.go:199] ekPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArjhtibVGL6gGSFhTfUxl
O3KOrmqfbXnx/T8pVu2eKvUofGJw+gqn87371svPk+qz/zsF3cSnKU+/3r4Ldwka
zRlKKSPSpWj4bj+Em+xylZ5rzOKpY2HOyyo+F3/iwHNHh8pFU/+vCSIDGr23kIzr
TzBi2JMQBvV6B+5x+QwCKxf/DT/ae4ezzT+7XzUlYINZIQugSp1vtY7keBY/h+YK
94rXASg/ol1jc2BDSUltUVgDuHbia+b9SM0dh9L0JjylleqxUlP+mfMsW+S4tQHg
Y8l62mjsu7NNccDDktnpgxkVBgi4xdwXj3leABkJ3wRKOomEu6RgX9ThQrsWb5xy
jQIDAQAB
-----END PUBLIC KEY-----
I0319 11:55:53.884157   29733 main.go:201] ======= Write (ekPub) ========
I0319 11:55:53.884232   29733 main.go:211] ======= CreateKeyUsingAuth ========
I0319 11:55:54.095693   29733 main.go:237] akPub: 0001000b00050072000000100014000b0800000000000100e57e9203052ddafd87321545967029ce7fa4c4fc4236de8590665fe28333647daefcd23643bcbbfb1d825bf9298052300d1f6863a488cc4bb73a0ebbb9f1df108e536b214a946504682e8fa280e472e59507b179eaf28e3d5bec954233d6c6e85baef395763d8de2d87d8aeb53d56e1d0388f6adc0b02ba4e61fea4da9006395984624e6a315ff963a28aa0ae22c4ac4dba9feb1634949762467b0016c7e52ce6147d68b926d958f1094f25cfeb60c973ee85610c347acf75dbaff6797a2d90fa9da72899fa79a457ef0f412d205b4a5ab2eb9d95efecd36df61ba69aa3220b548b412d834fc58e3543e093575ab6559be64cd701060dcdb2d48b252315bcb17,
I0319 11:55:54.095729   29733 main.go:238] akPriv: 0020e64016d1338df161f96adfd7e088dc31d4924bf9f227236c99d49f7d2e8617aa0010fb27676b91d0f3783351fd59ce441fe83ece7de6a2c09e6fb6b43a0a44e0086855511e9c9aa5968f7c3aac8c295bec46b6383a05dfcd3cab5138bbe61a1be54783eb1d2dd5f5ece2a9c5e2cdf69d2ca1987ecbec8377da4c6e0d6e83e2d4ba817ccc06d4708730970cdfabc0d5068947a3a1c5a958e2633f06d3c520d71e381c4c06dcf6521bafbb311305cbfede1410b4fe5578d7c994eb74b610a8f3602323fb76a9d76f63b5fdcd49cd7c3d4be49be6abdcbc704ac20c5f4f,
I0319 11:55:54.095763   29733 main.go:249] ======= ContextSave (ek) ========
I0319 11:55:54.105000   29733 main.go:260] ======= ContextLoad (ek) ========
I0319 11:55:54.112180   29733 main.go:270] ======= LoadUsingAuth ========
I0319 11:55:54.119754   29733 main.go:298] ak keyName 000bbcb80f17f265cc5e2f234e5fa0d3279769863fa016dec2e5ff4cd836353ac08d
I0319 11:55:54.119779   29733 main.go:300] ======= Write (akPub) ========
I0319 11:55:54.119840   29733 main.go:305] ======= Write (akPriv) ========
I0319 11:55:54.124907   29733 main.go:106] keyNameBytes  000bbcb80f17f265cc5e2f234e5fa0d3279769863fa016dec2e5ff4cd836353ac08d
```

Note, PCR Value `23` is: `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`

```bash
# ls
akPriv.bin  akPub.bin  attest.bin  ek.bin  ekPub.bin  go.mod  go.sum  main.go
```

#### Quote

Transfer `akPub.bin` `ek.bin` to your laptop which wants to make the VM quote

If using Google CLoud, you can extract the public RSA key from `ek.bin` and compare that to
`$  gcloud compute instances get-shielded-identity sev-instance-1  --format="value(encryptionKey.ekPub)"`

(that will ensure the `ek.bin` is really from the VM in question)

Pick a one time nonce (below its `foo` and request a quote that returns pcr value `23`)
(TODO: the code below does not support multiple PCR registers in the quote...)


On the shieldedVM, run:

```bash
# go run main.go --mode quote --secret=foo  --pcr 23 --logtostderr=1 -v 5
I0319 11:56:02.214666   29779 main.go:314] ======= init Quote ========
I0319 11:56:02.229965   29779 main.go:341] ======= Load (ek.bin) ========
I0319 11:56:02.237925   29779 main.go:351] ======= Read (akPub) ========
I0319 11:56:02.237963   29779 main.go:356] ======= Read (akPriv) ========
I0319 11:56:02.237981   29779 main.go:362] ======= LoadUsingAuth ========
I0319 11:56:02.245049   29779 main.go:390] ak keyName 000bbcb80f17f265cc5e2f234e5fa0d3279769863fa016dec2e5ff4cd836353ac08d
I0319 11:56:02.245068   29779 main.go:392] ======= Start Quote ========
I0319 11:56:02.246645   29779 main.go:399] PCR 23 Value f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b 
I0319 11:56:02.252078   29779 main.go:408] Quote Hex ff54434780180022000b5b1bd215e8585f3b528c297a2f2fbe435d87c38d5f2eef135c4d3277d963ae180003666f6f000000000732e39b000000020000000001201605110016280000000001000b030000800020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9
I0319 11:56:02.252119   29779 main.go:409] Quote Sig 0c3cdc350c19392a0c7d106456d997cac614637d54f502541afc0045cbbdf503b4d04f1911fd99ca16dcbc6df181532d1fda7797ebfc57fe8c865d87628c37f0749d79a76be2f1d19d2692e5069fea5f55b84347f3c02a5927fea918a6b6cb3115fcead4c07a8c04123ed1332b744dd5989443079fca5c66ccf4073cc37b7ecf4fa9d5201b11a15b0b99b88a998520d2ac9522bba7dbd885ba57fb81e0ba09b2ed826ab0319c6b6ee1eac464f177f43eab2ac651f9cafd4023094e4c75201f87677437c41ded4791e7216b17fd54067b90c2882e8b7de81375ef04bf7f3a79b5de77e18c82fae1280dfb325910143ffca8848a4989f21472d071e342c22f164c
I0319 11:56:02.252133   29779 main.go:411] ======= Write (attestion) ========
I0319 11:56:02.252239   29779 main.go:417] ======= Write (sig) ========
```

Quote key serialized into `attest.bin`, the RSA Signature is `sig.bin` (as rsa256)
```bash
# ls 
akPriv.bin  akPub.bin  attest.bin  ek.bin  ekPub.bin  go.mod  go.sum  main.go  sig.bin
```


#### Verify

Return `attest.bin` and `sig.bin` back to the laptop and verify the signature and that the attestation includes the nonce, pcr value you expect

```bash
# go run main.go --mode verify --secret=foo  --pcr 23 --logtostderr=1 -v 5
I0319 11:56:09.811280   29825 main.go:427] ======= init Quote ========
I0319 11:56:09.828184   29825 main.go:449] Handle 0x80000000 flushed
I0319 11:56:09.829854   29825 main.go:458] PCR 23 Value f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b 
I0319 11:56:09.829875   29825 main.go:460] ======= Read (akPub) ========
I0319 11:56:09.829908   29825 main.go:466] ======= LoadUsingAuth ========
I0319 11:56:09.829922   29825 main.go:468] ======= Read and Decode(attestion) ========
I0319 11:56:09.829965   29825 main.go:478] Attestation ExtraData (nonce) foo 
I0319 11:56:09.830017   29825 main.go:479] Attestation PCR# [23] 
I0319 11:56:09.830036   29825 main.go:480] Attestation Hash# e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9 
I0319 11:56:09.830043   29825 main.go:482] ======= Read (sig) ========
I0319 11:56:09.830076   29825 main.go:494] original PCR Value: f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b        --> %!x(MISSING)
I0319 11:56:09.830096   29825 main.go:495] sha256 of original PCR Value: --> e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9
I0319 11:56:09.830113   29825 main.go:497] ======= Decoding Public ========
I0319 11:56:09.830238   29825 main.go:508] Attestation Verified 
```

Note the nonce `foo` we set earlier is included inside the attestation which also echos the PCR (its hash, rather). eg

PCR Value for 23 is `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`
sha356has of that is `e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9`  (which is what we got in the attestation)

Finally, (and critically) we used the akPublic key to verify the attestation object is signed by the AK we already setup.