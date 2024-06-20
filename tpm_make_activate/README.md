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

```  