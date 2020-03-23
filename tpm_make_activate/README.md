# Make-Activate Credential 

- [https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
- [https://sourceforge.net/projects/ibmtpm20acs/](https://sourceforge.net/projects/ibmtpm20acs/)
- [https://github.com/google/go-attestation/blob/master/docs/credential-activation.md](https://github.com/google/go-attestation/blob/master/docs/credential-activation.md)


## TPM-A

### Create EK

```bash
$ tpm2_createek -c A-ek.ctx -G rsa -u A-ek.pub
```


Optionally view specifications of the EK (eg. decrypt attribute)

```bash
$ tpm2_readpublic -c A-ek.ctx -o A-ek.pem -f PEM
    name: 000b99eff3f84d1a80a54debb4336916d93b70607c25675804009daaf296cea0547d
    qualified name: 000b2fa731ca4d92e57668631ca56076fc095f079c5a625082b21e89974e44a0600e
    name-alg:
      value: sha256
      raw: 0xb
    attributes:
      value: fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt
      raw: 0x300b2
```


### Create AK

```bash
$ tpm2_createak -C A-ek.ctx -c A-ak.ctx  -n A-ak.name -u A-ak.pub
  loaded-key:
    name: 000badac1a2beb5d2b28f5d141f0a63098ab9b728d31094db016c24666e25ce7c774
```

Optionally view specifications of the AK (eg. sign attribute)

```bash
$ tpm2_readpublic -c A-ak.ctx
    name: 000badac1a2beb5d2b28f5d141f0a63098ab9b728d31094db016c24666e25ce7c774
    qualified name: 000b638b73f6ce59b827ecbc6b15208faeebcce9bdf7502978ed79ba274a38e409c9
    name-alg:
      value: sha256
      raw: 0xb
    attributes:
      value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign
      raw: 0x50072
```

Copy **A-ek.pub A-ak.pub** to TPM-B

## TPM-B


```bash
tpm2_loadexternal -C n -u A-ak.pub -c A-ak.ctx
tpm2_readpublic -c A-ak.ctx
```

Note that the `name` matches what we had on the shieldedVM (`000badac1a2beb5d2b28f5d141f0a63098ab9b728d31094db016c24666e25ce7c774`)


>> On GCP:
Convert PEM format of EKPub to TPM2 tools struct file:  A-ek.pem --> A-ek.pub
You can get A-ek.pem on Google cloud by using the `gcloud` cli:
  `gcloud compute instances get-shielded-identity instance-1 --format="value(encryptionKey.ekPub)" > A-ek.pem`
Then convert from PEM to TPM format using this utility:
   [ptmtotss.go](https://github.com/salrashid123/tpm2/blob/master/utils/pemtotss.go)



### MakeCredential

Use the key "name" defined earlier and the converted `A-ek.pub` to seal the secret.  You are not using the TPM (`-T none`) 


```bash
$ echo "meet me at..." > secret.txt

export Loadkeyname=000badac1a2beb5d2b28f5d141f0a63098ab9b728d31094db016c24666e25ce7c774
tpm2_makecredential -e A-ek.pub -s secret.txt -n $Loadkeyname -o mkcredential.out -T none
```


Copy **mkcredential.out** to TPM-A


## TPM-A

### Start AuthSession
```bash
tpm2_startauthsession --policy-session -S session.ctx
TPM2_RH_ENDORSEMENT=0x4000000B
tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT
tpm2_flushcontext --transient-object
```

```bash
$ tpm2_activatecredential -c A-ak.ctx -C A-ek.ctx -i mkcredential.out -o actcred.out -P"session:session.ctx"

more actcred.out 
"meet me at.."
```

---

To Assert AK/EK relationship between TPM-A and TPM-B

1) on TPM-A

Create EK, AK:

```bash
// 1. TPM-A
# go run main.go --mode createKey --pcr 23 --logtostderr=1 -v 5
I0318 16:02:03.241784    4293 main.go:121] ======= Init CreateKeys ========
I0318 16:02:03.254537    4293 main.go:143] Handle 0x80000000 flushed
I0318 16:02:03.254560    4293 main.go:148] 1 handles flushed
I0318 16:02:03.256210    4293 main.go:155] PCR 23 Value f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b 
I0318 16:02:03.256229    4293 main.go:160] ======= createPrimary ========
I0318 16:02:03.383996    4293 main.go:192] ekPub Name: 000bae2e4d564b3592c3781c6e774ffb8ca680f9d103b80c1ab1aa058e5f2b1412f7
I0318 16:02:03.384031    4293 main.go:193] ekPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArjhtibVGL6gGSFhTfUxl
O3KOrmqfbXnx/T8pVu2eKvUofGJw+gqn87371svPk+qz/zsF3cSnKU+/3r4Ldwka
zRlKKSPSpWj4bj+Em+xylZ5rzOKpY2HOyyo+F3/iwHNHh8pFU/+vCSIDGr23kIzr
TzBi2JMQBvV6B+5x+QwCKxf/DT/ae4ezzT+7XzUlYINZIQugSp1vtY7keBY/h+YK
94rXASg/ol1jc2BDSUltUVgDuHbia+b9SM0dh9L0JjylleqxUlP+mfMsW+S4tQHg
Y8l62mjsu7NNccDDktnpgxkVBgi4xdwXj3leABkJ3wRKOomEu6RgX9ThQrsWb5xy
jQIDAQAB
-----END PUBLIC KEY-----
I0318 16:02:03.384057    4293 main.go:195] ======= Write (ekPub) ========
I0318 16:02:03.384179    4293 main.go:205] ======= CreateKeyUsingAuth ========
I0318 16:02:03.486335    4293 main.go:231] akPub: 0001000b00050072000000100014000b0800000000000100a0f2b73f6712cf16145a275815b00e2c4b9fcd2096bd1d01f2989df328d0f039901b05f4e9a503e9be9848aa3625a4684b5a9204df92025510fd90649330bde44dd41dbff6d5445cbc2dd7932d81ffd92a0790aad3dc41f67cf791d185aac88ec9f3b024de863d4b7765e85b768b785799285b47158efbf38f1330f43b02d911e252a0333c809fb09bdb91e302636f3fe425ffd4229369ef609466babc6313a5ff57f0e0daa15ae3d79b34a37c557861451f6ebbb1fa310180fcd5b8e797fdff39d938bd39a71a667559b35e52ef3d926eef0cac660f1c8c8e9abfaf3467d56bb36e9fcbb94ee45ac817dda5f211a3b6ca614ab92ef1a5975d1330f4241f0e87,
I0318 16:02:03.486360    4293 main.go:232] akPriv: 0020e51e369d1c6b720365bf92c17d7ea516d5e10f92111072cb257c197150657c3e0010e3680b70fc09ee2b2bb3b1cf6a3609e6096df1f1b8c8c6279c53304f0b7f2689e60234ae3d979e47d12bf5dd804a5350ee3b76849b9d253c4cf77cf4b6bdb46fb427eed25f73631913437af70f32430df69ad2fd147f9e2bb604327c6f25c6ae4031334cf3a0f28da18d65ac4cbe87aa5b67b1d24121f6ccac7f601b85bcab94953c70b7c6488429bf66a484b71305aaaac8e8f4513268d0db4d146db0ddda41dcad33721c8eb883c8465cdef28047049609dfe2aed2d2645bbb,
I0318 16:02:03.486394    4293 main.go:243] ======= ContextSave (ek) ========
I0318 16:02:03.495544    4293 main.go:254] ======= ContextLoad (ek) ========
I0318 16:02:03.502674    4293 main.go:264] ======= LoadUsingAuth ========
I0318 16:02:03.510068    4293 main.go:292] ak keyName 000b473b89a90439d6434604364e5033dcdb8130abe18f165619fa9b6fb677c5f472
I0318 16:02:03.510092    4293 main.go:294] ======= Write (akPub) ========
I0318 16:02:03.510135    4293 main.go:299] ======= Write (akPriv) ========
I0318 16:02:03.515103    4293 main.go:102] keyNameBytes  000b473b89a90439d6434604364e5033dcdb8130abe18f165619fa9b6fb677c5f472
```

```
# ls
akPriv.bin  akPub.bin  ek.bin  ekPub.bin  go.mod  go.sum  main.go
```

Copy `ekPub.bin`, `akPub.bin` to TPM-B

2) on TPM-B

Use EK, AK from A to encrypt some data by specifying the "keyName" of the AK and save it into a credentialBlob

```bash
# ls
akPub.bin  ekPub.bin  go.mod  go.sum  main.go
```

```bash
# go run main.go --mode makeCredential  --pcr 23 --logtostderr=1 -v 5
I0318 16:06:44.392391     895 main.go:308] ======= init MakeCredential ========
I0318 16:06:44.448241     895 main.go:335] ======= Load (ekPub.bin) ========
I0318 16:06:44.451619     895 main.go:351] ======= Read (akPub) ========
I0318 16:06:44.454449     895 main.go:366]  Loaded KeyName 000b473b89a90439d6434604364e5033dcdb8130abe18f165619fa9b6fb677c5f472
I0318 16:06:44.454470     895 main.go:368] ======= MakeCredential ========
I0318 16:06:44.457465     895 main.go:374] credBlob 0020d29018473c11938f6abd5d9bb99b47ddfc9c2ddd16e14d8b817c6c2a41dd189b5d83efcb974a1b1cd2c56702f9520b
I0318 16:06:44.457487     895 main.go:375] encryptedSecret0 6eeba622e16a69574b43478805028be0b55267ef1c0612d48dbb7bd3d26d90fc63d641e72696b4c2145c0a62af2bcf12c27620b51a55e2473f527b07f29b2a1c8a2cafe832b52cf3b68f7662363c2e776f26fb538398c4b51e60050b855e4d43165ffbdf222378173c4b3fcea4eb355784439bd926face03407bb33c346c229ac1bb5d1910d52f9c0236249cb809200db9d144360693705ca6fc29501bb209b250e7f52da78b37c8601403611ada0a079160ddcafcc086e3694e39fa110ccb397915e817240180f7410a45f8759443ba02e51e2de355b80e1f169c05f2eecfdfb5e2efe04e4844798d6118c2b7b87d73c75c75967ec6d64f090be633a4463bed
I0318 16:06:44.457522     895 main.go:377] ======= Write (credBlob) ========
I0318 16:06:44.457603     895 main.go:383] ======= Write (encryptedSecret0) ========
```

Transfer `credBlob`, `encryptedSecret0` to TPM-A

3) On TPM-A, 
Unwrap the encryptedSecret to reveal the  secret TPM-B sent.

You can return the _unencrypted_ secret to TPM-A and show that TPM-B 'owns' EK and AK

```bash
# ls
akPriv.bin  akPub.bin  credBlob.bin  ek.bin  ekPub.bin  encryptedSecret0.bin  go.mod  go.sum  main.go
```

```bash
# go run main.go --mode activateCredential  --pcr 23 --logtostderr=1 -v 5
I0318 16:10:05.021315    4792 main.go:393] ======= init ActivateCredential ========
I0318 16:10:05.171568    4792 main.go:420] ======= ContextLoad (ek) ========
I0318 16:10:05.179348    4792 main.go:430] ======= Read (akPub) ========
I0318 16:10:05.179382    4792 main.go:435] ======= Read (akPriv) ========
I0318 16:10:05.179410    4792 main.go:441] ======= Read (credBlob) ========
I0318 16:10:05.179444    4792 main.go:446] ======= Read (encryptedSecret0) ========
I0318 16:10:05.179471    4792 main.go:452] ======= LoadUsingAuth ========
I0318 16:10:05.186175    4792 main.go:479] keyName 000b473b89a90439d6434604364e5033dcdb8130abe18f165619fa9b6fb677c5f472
I0318 16:10:05.186197    4792 main.go:481] ======= ActivateCredentialUsingAuth ========

I0318 16:10:05.197259    4792 main.go:529] recoveredCredential1 meet me at...
```

### Using TPM2Tools to change PCR value

```bash
tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```  