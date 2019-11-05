# Make-Activate Credential 

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

>> Copy `A-ak.pub` to TPM-B

## TPM-B


```bash
$ tpm2_loadexternal -C n -u A-ak.pub -c A-ak.ctx
$ tpm2_readpublic -c A-ak.ctx
```

Note that the `name` matches what we had on the shieldedVM (`000badac1a2beb5d2b28f5d141f0a63098ab9b728d31094db016c24666e25ce7c774`)


>> Convert A-ek.pem --> A-ek.pub



### MakeCredential

Use the key "name" defined earlier and the converted `ek.pub` to seal the secret.  You are not using the TPM (`-T none`) 


```bash
$ echo "meet me at..." > secret.txt

$ export Loadkeyname=000badac1a2beb5d2b28f5d141f0a63098ab9b728d31094db016c24666e25ce7c774
$ tpm2_makecredential -e A-ek.pub -s secret.txt -n $Loadkeyname -o mkcredential.out -T none
```


>> Copy mkcredential.out to TPM-A


## TPM-A

### Start AuthSession
```bash
$ tpm2_startauthsession --policy-session -S session.ctx
$ TPM2_RH_ENDORSEMENT=0x4000000B
$ tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT
$ tpm2_flushcontext --transient-object
```

```bash
$ tpm2_activatecredential -c ak.ctx -C ek.ctx -i mkcredential.out -o actcred.out -P"session:session.ctx"

more actcred.out 
"meet me at.."
```

---

To Assert AK/EK relationship between TPM-A and TPM-B

1) on TPM-A

Create EK, AK:

```
// 1. TPM-A
// # go run main.go --mode createKey --pcr 23 --logtostderr=1 -v 5
// I1028 23:31:03.861516    9880 main.go:119] ======= Init CreateKeys ========
// I1028 23:31:03.874301    9880 main.go:146] 0 handles flushed
// I1028 23:31:03.876049    9880 main.go:153] PCR 23 Value 536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c
// I1028 23:31:03.876188    9880 main.go:158] ======= createPrimary ========
// I1028 23:31:03.948743    9880 main.go:190] ekPub Name: 000b556f027181efe58ace1ab80e959d296ca62b569b3496876fbd35ad7f5bc3b549
// I1028 23:31:03.948948    9880 main.go:191] ekPub:
// -----BEGIN PUBLIC KEY-----
// MIIBIjANBgk..B
// -----END PUBLIC KEY-----
// I1028 23:31:03.949427    9880 main.go:193] ======= CreateKeyUsingAuth ========
// I1028 23:31:04.288286    9880 main.go:219] akPub: 0001000b0005007200000010...,
// I1028 23:31:04.288541    9880 main.go:220] akPriv: 0020f4a18aa5c805ae10d9c...
// I1028 23:31:04.288675    9880 main.go:231] ======= ContextSave (ek) ========
// I1028 23:31:04.298607    9880 main.go:242] ======= ContextLoad (ek) ========
// I1028 23:31:04.306872    9880 main.go:252] ======= LoadUsingAuth ========
// I1028 23:31:04.313794    9880 main.go:280] ak keyName 000bf0fe0287e2320bf3cc4c984b628cd00c9edb127b33b02812592bcd7eb70ff705
// I1028 23:31:04.313936    9880 main.go:282] ======= Write (akPub) ========
// I1028 23:31:04.314130    9880 main.go:287] ======= Write (akPriv) ========
// I1028 23:31:04.316779    9880 main.go:100] keyNameBytes  000bf0fe0287e2320bf3cc4c984b628cd00c9edb127b33b02812592bcd7eb70ff705


2) on TPM-B

Use EK, AK from A to encrypt some data by specifying the "keyName" of the AK and save it into a credentialBlob

// 2. TPM-B
// # go run main.go --mode makeCredential  --pcr 23 --logtostderr=1 -v 5
// I1028 23:31:39.673176    9912 main.go:296] ======= init MakeCredential ========
// I1028 23:31:39.689361    9912 main.go:323] ======= ContextLoad (ek) ========
// I1028 23:31:39.697645    9912 main.go:334] ======= Read (akPub) ========
// I1028 23:31:39.701085    9912 main.go:349]  Loaded KeyName 000bf0fe0287e2320bf3cc4c984b628cd00c9edb127b33b02812592bcd7eb70ff705
// I1028 23:31:39.701216    9912 main.go:351] ======= MakeCredential ========
// I1028 23:31:39.704640    9912 main.go:357] credBlob 0020cfb47420b0582aa3b83a87c09...
// I1028 23:31:39.704769    9912 main.go:358] encryptedSecret0 4b4238588dc33c8828a0f...
// I1028 23:31:39.704867    9912 main.go:360] ======= Write (credBlob) ========
// I1028 23:31:39.705042    9912 main.go:366] ======= Write (encryptedSecret0) ========

Transfer credBlob, encryptedSecret0 to TPM-A

3) On TPM-A, 
Unwrap the encryptedSecret to reveal the  secret TPM-B sent.

You can return the encrypted secret to TPM-A and show that TPM-B 'owns' EK and AK

// 3. TPM-A
// # go run main.go --mode activateCredential  --pcr 23 --logtostderr=1 -v 5
// I1028 23:31:50.397101    9957 main.go:376] ======= init ActivateCredential ========
// I1028 23:31:50.415278    9957 main.go:403] ======= ContextLoad (ek) ========
// I1028 23:31:50.423860    9957 main.go:413] ======= Read (akPub) ========
// I1028 23:31:50.424108    9957 main.go:418] ======= Read (akPriv) ========
// I1028 23:31:50.424291    9957 main.go:424] ======= Read (credBlob) ========
// I1028 23:31:50.424393    9957 main.go:429] ======= Read (encryptedSecret0) ========
// I1028 23:31:50.424492    9957 main.go:435] ======= LoadUsingAuth ========
// I1028 23:31:50.432549    9957 main.go:462] keyName 000bf0fe0287e2320bf3cc4c984b628cd00c9edb127b33b02812592bcd7eb70ff705
// I1028 23:31:50.432729    9957 main.go:464] ======= ActivateCredentialUsingAuth ========
// I1028 23:31:50.447202    9957 main.go:512] recoveredCredential1 meet me at...
```