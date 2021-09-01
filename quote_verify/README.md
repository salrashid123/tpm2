
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

Golang quote/verify and eventlog verification:


* debain10, sha1, with secureboot: PCR:0 `0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea`
* ubuntu21, sha256, without secureboot: PCR:0 `24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f`

- [https://github.com/google/go-tpm-tools/blob/master/server/eventlog_test.go#L226](https://github.com/google/go-tpm-tools/blob/master/server/eventlog_test.go#L226)

```
gcloud compute instances create tpm-debian \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-10-buster-v20210817 --image-project=debian-cloud --boot-disk-device-name=tpm-debian \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```


```
gcloud compute ssh tpm-debian

apt-get update
apt-get install gcc libtspi-dev wget -y


wget https://golang.org/dl/go1.17.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz
```


```log
$ go run main.go  --secret=foo  --pcr 0 --pcrValue 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea --logtostderr=1 -v 5 

I0830 21:09:23.409440    7485 main.go:117] ======= Init CreateKeys ========
I0830 21:09:23.424780    7485 main.go:144] 0 handles flushed
I0830 21:09:23.426713    7485 main.go:151] PCR 0 Value 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea 
I0830 21:09:23.426746    7485 main.go:156] ======= createPrimary ========
I0830 21:09:23.560841    7485 main.go:188] ekPub Name: 000b24516b90809f3fa0d6881b2b2da2d43710fe10ff3df765fee28288501806fae7
I0830 21:09:23.560881    7485 main.go:189] ekPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA84oNOTCWL54gk+7sJnES
hpOG+xZBQUJjvQAN1bFOJBkok9IHx/QgzxM+7UxNA47M3HIcseOQnech+4q0WnKn
LNDjfPPLdLHCUDUqi6BBAO4d8r5p+Jl7jCwAueoguKKONeTQ13vJzYfEifBZwNWk
+pBO7SmFuGHYDkWkpd6nIB1kHBniylB1o2KyF437Gbk91bC5LIkHFgO2qnURxKVL
p/iDcaUkL0+6Kl1kn5hTtoOH7YScNHiTeBmZkh5AOgTVhDxpBsX0NtPxZ/EXBGaE
DhbEA4gMQDIrwWBZCQxY0obmn0UmvRZwjikigvFgxKizYN59uTcfCuXX2Ff+cj2j
TQIDAQAB
-----END PUBLIC KEY-----
I0830 21:09:23.560920    7485 main.go:191] ======= Write (ekPub) ========
I0830 21:09:23.561091    7485 main.go:201] ======= CreateKeyUsingAuth ========
I0830 21:09:23.716203    7485 main.go:227] akPub: 0001000b00050072000000100014000b0800000000000100af65ca0336992a09d9593c7916d5cacbbbff9700ee6b81bbddd063813b38957b94dd08ba0cc65ed28e7c1e98eac9b6fb2cac9bfce089491946308a7cd6ec9ada207180153e7a0898bd41e2772d22523837bf242387643a1791d9e9abff7bf243ae8bcc950bc1e79b78b4593fd239ba3f90ff8c1c16f407c6b68ca2ed2e18456183c9fdd544bc353e7de7c819e27fae010e649ce0588f5575a0f1f04cccc6814224dc04e9d0f12ce66235ea3d842fe6b376ba390d8ceb52c603daa61e742270afd6bd8ec7a99a8258bcaefb98a3a3d5b63a501a2063a620430f44ab77122fbf5d3ae431fb6e8504f4755f7c5c955b7a0ab4939ed307ceea0284f23cefc9bf4a99,
I0830 21:09:23.716244    7485 main.go:228] akPriv: 002041e31976a4efcb882d83e2cba75530285852df315a47d20f4e60b6c7f1790baa0010a3dad5c92e3cc5475a71ca44bf4becd625dd3f4f2143710c4fc98d18e4b8a1ae390fde6c7e681a0920c59f0a7e47cec465f530d8a1ccb336b9b0f6a1527c2ae84180e133ede28d7d1ec8ef8d7ee31ae26af910f6340a78b04ab5924bb579e959ab530cb2353f2b1bc1d181ad92baf63fcbe317df2749ac741f352613a3855830ee7bc2bb742b5385552b3f667b70dcbd6816d3434516bec11f86cd81214440c450a82ee36b2d534da5873faece539d1561c643ec030e381ded4b,
I0830 21:09:23.716273    7485 main.go:239] ======= ContextSave (ek) ========
I0830 21:09:23.727232    7485 main.go:250] ======= ContextLoad (ek) ========
I0830 21:09:23.735647    7485 main.go:260] ======= LoadUsingAuth ========
I0830 21:09:23.743938    7485 main.go:288] ak keyName 0022000bac5a397e4541d23762e92dc803c574c0bee8e4f333efc5dfe9fe30cb95f6faf8
I0830 21:09:23.744016    7485 main.go:290] ======= Write (akPub) ========
I0830 21:09:23.744238    7485 main.go:295] ======= Write (akPriv) ========
I0830 21:09:23.749672    7485 main.go:99] keyNameBytes  0022000bac5a397e4541d23762e92dc803c574c0bee8e4f333efc5dfe9fe30cb95f6faf8 
I0830 21:09:23.749707    7485 main.go:304] ======= init Quote ========
I0830 21:09:23.755700    7485 main.go:331] ======= Load (ek.bin) ========
I0830 21:09:23.764684    7485 main.go:341] ======= Read (akPub) ========
I0830 21:09:23.764792    7485 main.go:346] ======= Read (akPriv) ========
I0830 21:09:23.764817    7485 main.go:352] ======= LoadUsingAuth ========
I0830 21:09:23.772574    7485 main.go:380] ak keyName 0022000bac5a397e4541d23762e92dc803c574c0bee8e4f333efc5dfe9fe30cb95f6faf8
I0830 21:09:23.772607    7485 main.go:382] ======= Start Quote ========
I0830 21:09:23.774392    7485 main.go:389] PCR 0 Value 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea 
I0830 21:09:23.780235    7485 main.go:398] Quote Hex ff54434780180022000b2dc333f890f4268e178912d6491f6b39f489cd0f12b0c9d7b515c92b5c391d6c0003666f6f00000000000a1ca500000008000000000120160511001628000000000100040301000000205338985c6393c540b8c2c9d9c69dde64144470c5076dd53dbc4b84753e0004ac
I0830 21:09:23.780277    7485 main.go:399] Quote Sig 4f87fe7eca504c45d4a822ac6671739082ea3599b590ac6b30767c9267e93ee91973aed76287b6773629820135c66b83389daa2f4cad391f66d52caee07b12f193067ae4b761d554fcaf293b39a6cd6c0b4309c2870f82b06ff7f45fc1e9099349d22614f5e3a561a6e90268584867f46f400e82e411a9d34f73ef17a7bec6c43b36803724d2f82ed084f4401183259575bea8e2f687055991beb0962019eb3c84b6a7c372ddcaa1f3578933c442fcdf431d50b2be9fd11de12109acd634121a34afe6d5af0ca60b98fcf92ba1f77dd9a6010983c09eadcc41723fef00099148a9f04786a306a73da5990d261dfcd127aacadbba5f2d10bbe4a0c05d35e167b5
I0830 21:09:23.780302    7485 main.go:401] ======= Getting EventLog ========
I0830 21:09:23.783316    7485 main.go:411] ======= init verify ========
I0830 21:09:23.786456    7485 main.go:427] PCR 0 Value 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea 
I0830 21:09:23.786484    7485 main.go:429] ======= Read (akPub) ========
I0830 21:09:23.786537    7485 main.go:435] ======= LoadUsingAuth ========
I0830 21:09:23.786554    7485 main.go:437] ======= Read and Decode(attestion) ========
I0830 21:09:23.786591    7485 main.go:443] Attestation ExtraData (nonce) foo 
I0830 21:09:23.786608    7485 main.go:444] Attestation PCR# [0] 
I0830 21:09:23.786637    7485 main.go:445] Attestation Hash# 5338985c6393c540b8c2c9d9c69dde64144470c5076dd53dbc4b84753e0004ac 
I0830 21:09:23.786660    7485 main.go:450] sha256 of original PCR Value: --> 5338985c6393c540b8c2c9d9c69dde64144470c5076dd53dbc4b84753e0004ac
I0830 21:09:23.786680    7485 main.go:452] ======= Decoding Public ========
I0830 21:09:23.786824    7485 main.go:463] Attestation Verified 
I0830 21:09:23.786930    7485 main.go:482] Event Type EV_S_CRTM_VERSION
I0830 21:09:23.786978    7485 main.go:483] PCR Index 0
I0830 21:09:23.787000    7485 main.go:484] Event Data 47004300450020005600690072007400750061006c0020004600690072006d0077006100720065002000760031000000
I0830 21:09:23.787022    7485 main.go:485] Event Digest 3f708bdbaff2006655b540360e16474c100c1310
I0830 21:09:23.787045    7485 main.go:482] Event Type EV_NONHOST_INFO
I0830 21:09:23.787060    7485 main.go:483] PCR Index 0
I0830 21:09:23.787073    7485 main.go:484] Event Data 474345204e6f6e486f7374496e666f0000000000000000000000000000000000
I0830 21:09:23.787084    7485 main.go:485] Event Digest 9e8af742718df04092551f27c117723769acfe7e
I0830 21:09:23.787094    7485 main.go:482] Event Type EV_SEPARATOR
I0830 21:09:23.787104    7485 main.go:483] PCR Index 0
I0830 21:09:23.787116    7485 main.go:484] Event Data 00000000
I0830 21:09:23.787126    7485 main.go:485] Event Digest 9069ca78e7450a285173431b3e52c5c25299e473
I0830 21:09:23.787135    7485 main.go:487] EventLog Verified 
```