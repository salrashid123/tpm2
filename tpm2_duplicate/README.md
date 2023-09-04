## TPM2_DUPLICATE


See: [Duplicating-Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)


# Duplicating Objects

Sample procedure to transfer an RSA key from one TPM to another. The RSA key
never leaves the protection of the two TPMs at anytime and cannot be decoded or
used on any other system even if it intercepted in transit.


This procedure will transfer an RSA key from `TPM-A` to `TPM-B`.  The key can be
generated via `openssl` and imported into `TPM-A` or generated directly on
`TPM-A`.

`TPM-B` will provide `TPM-A` the public portion of a keypair it owns that allows
a sealed transfer.  This tutorial uses the following two APIs

* [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md)
* [tpm2_import](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md)


## On TPM-B

Create a parent object that will be used to wrap/transfer the PEM file
```
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_create  -C primary.ctx -g sha256 -G rsa \
-r new_parent.prv  -u new_parent.pub \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"

```

Copy `new_parent.pub` to `TPM-A`.  The copy steps assumes attestation was done
previously and that `TPM-A` trusts the `new_parent.pub` issued by `TPM-B`

```bash
# copy new_parent.pub from B to A
scp new_parent.pub  alice@tpm-A:
```

## On TPM-A


Create root object and auth policy allows duplication only

```
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_startauthsession -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate

tpm2_flushcontext session.dat

rm session.dat
```

Generate an RSA keypair on TPM to transfer  (note the passphrase is 'foo')

```
tpm2_create -C primary.ctx -g sha256 -G rsa -p foo -r key.prv \
-u key.pub  -L dpolicy.dat -a "sensitivedataorigin|userwithauth|decrypt|sign"
  
    [ FOR AES key use -G aes:
       tpm2_create -C primary.ctx -g sha256 -G aes -p foo -r key.prv -u key.pub  -L dpolicy.dat -a "sensitivedataorigin|userwithauth|decrypt|sign" ]

tpm2_load -C primary.ctx -r key.prv -u key.pub -c key.ctx

tpm2_readpublic -c key.ctx -o dup.pub
````

Test sign and encryption locally (so we can compare later that the same key was transferred).

```
echo "meet me at.." >file.txt
tpm2_rsaencrypt -c key.ctx  -o data.encrypted file.txt
tpm2_sign -c key.ctx -g sha256 -f plain -p foo -o sign.raw file.txt

   [ for AES key, use
     tpm2_encryptdecrypt -Q -c key.ctx -p foo -o encrypt.out secret.dat ]
```

Compare the signature hash (we will use this later to confirm the key was transferred to TPM-B):

```
sha256sum sign.raw

a1b4e3fbaa29e6e46d95cff498150b6b8e7d9fd21182622e8f5a3ddde257879e
```

Start an auth session and policy command to allow duplication
```
tpm2_startauthsession --policy-session -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
```

Load the new_parent.pub file transferred from `TPM-B`
```
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx
```

Start the duplication
```
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  \
-p "session:session.dat" -r dup.dup -s dup.seed
```

Copy the following files to TPM-B:
* dup.pub
* dup.dup
* dup.seed
* (optionally data.encrypted just to test decryption)

```bash
scp dup.pub  bob@tpm-b:
scp dup.dup  bob@tpm-b:
scp dup.seed  bob@tpm-b:
```
## On TPM-B

Start an auth,policy session
```
tpm2_startauthsession --policy-session -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
```

Load the context we used to transfer
```
tpm2_flushcontext --transient-object

tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx
```

Import the duplicated context against the parent we used

```
tpm2_import -C new_parent.ctx -u dup.pub -i dup.dup \
   -r dup.prv -s dup.seed -L dpolicy.dat
```

Load the duplicated key context 
```
tpm2_flushcontext --transient-object

tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx
```

Test the imported key matches

* Sign

```bash
echo "meet me at.." >file.txt

tpm2_sign -c dup.ctx -g sha256 -o sig.rss -p foo file.txt

dd if=sig.rss of=sign.raw bs=1 skip=6 count=256
```

Compare the signature file hash:

```bash
$ sha256sum sign.raw

a1b4e3fbaa29e6e46d95cff498150b6b8e7d9fd21182622e8f5a3ddde257879e
```

* Decryption

```
tpm2_flushcontext --transient-object

tpm2_rsadecrypt -p foo -c dup.ctx -o data.ptext data.encrypted

# cat data.ptext 
meet me at..
```

---

from [gcp_tpm_sealed_keys#transfer-rsa-key-with-password-policy-from-a-b](https://github.com/salrashid123/gcp_tpm_sealed_keys#transfer-rsa-key-with-password-policy-from-a-b)

#### Transfer RSA key with password policy from A->B

If you want to see what the sealed rsa transfer looks like using `tpm2_tools` and a password policy, then using sample from [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md)



- TPM-B

```bash
$ tpm2_createprimary -c primary.ctx
$ tpm2_readpublic -c primary.ctx -o primary.pub

$ tpm2_print -t TPM2B_PUBLIC  primary.pub

## read as PEM
$ tpm2_readpublic -f PEM -c primary.ctx  -o primary.pem
```

copy primary.pub to TPM-A

- TPM-A

```bash
# $ openssl genrsa -out rsa.pem

$ cat rsa.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwlmH3di2JpoBUtE6JKXthqPnS2tZXqFS302RuQavVFwZ7l7z
MbgAEvqzrF+JIhGr4LEVJwfNBbzOCNu+fT55Vq5/Pt3hCibb7/B2N4I4trfjdt2t
7+Kd8h4plMrszfY/gvK7MQBINe0spSAPWdnWkGXFY4emRbwo3NmjpLaSv0489LTD
gOA9uaPEk2dudrGyACWmbGMKm/2mxGVCuFIvtqW/Az/tpJ8mWVZZX4kmOlIIKZSd
ctF3wvyv1fTVwcmxfqGeFkN5WcSvUipZguRVNgLPBuYIMhC8+H+C1bw8FV+9TLs6
sHMSHp9GfwDQnkdnx4kInxhkD3/AT3B1gUZiKwIDAQABAoIBAQCMzH4A+7pi1tm0
nP2phUhCbcXoPro9M1StkC3NRQmKbTsgFUvMrkfneBbo/0GDHBhQLRps71raGEGP
61ris3sGkF6BNg+N4j8eYi/S4RWjUi+JcupLSvswaCepsyXBxO+YN6/jvReTceMR
MdvNNWMbs49AHwsXpExaS5Yhg19nFcxJd6MOfmFvJ9UimPh7XgSCtmrdQ0XKPoxG
7vWaNERN7xqgDyYG0oR2i+/4sDZ5KolehXNjmdDD/8qwa4PVEgVBn9QaypHNC1nD
njG39hIPvdN1Ix8kn7jtzuB0qePnQLC+87R4KAOXFNG3FGgUmDFVAIy7CSLcAJNG
G8yQy/GhAoGBAO/aXjBK6QnE19eDbm/mKzZB2+IVrdVe7cuORrqBlRrTf8NbqxtT
aIBd3kBfuGGLwuJLWLsyy1wc/rx0SZ/MOOWxk+/QQKhvp4dxn2imCBoNvozU6/Xg
I5Iawos6rwM8VGAcaaRa/atlGUpmSp5cVBl//HKAO5PyKS/PIxPjfaZxAoGBAM9u
9VoEx1yEK4cJDIX1KWIBCMq9lXBYv09WsLERKdfo4hMwbuv2CMMadvqPEh3h+dKr
4r7/cyrIyx4ydkRLBD1JC0yMUTMftqm5WBrImUvjpSNt8oV90R8VBDrfHzpRrFfj
9lEm0mKdl2Kn1R+Gu50aHNSwna+GhSjOgsHPK7hbAoGBALKaN6LcVTV6B4OqkfTv
PuQzHGn43K3S912pP0+oKICGV1AAlaROcrWLsHDdFi5E5USe+J7EzxtzV9i6+wvs
Bb48gj2EJHGIWwaHfD1vzP6hl2/FKUO4uKQWGyGT/Dh7lxTOc3f4bYZQTQnSq+PK
OrGWVURp6nNbUoIQSz2HG8xxAoGBAMAV7/28DyENA4G4T3B85iVq78lOZePzSrUd
geF2E1lsvm0mnJDE9Lg2+ZZshkpFyCHeKcrUosErz2vXLs1u6i4WRfBMv6Sn6W6h
w4SJ3er4kyOL3Njg+ZXe0Fvz4ecPWpjI8H+Vg5zuchFZeXIIQhPo6mnKYzr3RrfT
BCKUxdehAoGAA2lkBrhF/kw9i4bQ+ohOcIaU6cqF9PSlYKT/2LbP19C7O9Sld9rH
mdvDiyyIs7fXWnCuxPwl8PSjDCXbUrij2lQmgCndPWT8w2U22Y/E9xpGOwIQBd+P
YQJn9mZMKihGI5E381Oicx4jCBzpnGrVJ13j5rgyPmom6X55U6rwH3E=
-----END RSA PRIVATE KEY-----

$ echo "meet me at.." >file.txt
$ openssl dgst -sha256 -sign rsa.pem  file.txt | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==


$ tpm2_startauthsession --policy-session -S session.dat
$ tpm2_policypassword -S session.dat -L policy.dat
$ tpm2_flushcontext session.dat
$ tpm2_duplicate -U primary.pub -G rsa -k rsa.pem -u rsa.pub -r rsa.dpriv -s rsa.seed -L policy.dat  -p testpassword
```

copy `rsa.pub`, `rsa.dpriv` and `rsa.seed` to `TPM-A`

- TPM-B

```bash
$ tpm2_import -C primary.ctx -G rsa -i rsa.dpriv -s rsa.seed -u rsa.pub -r rsa.priv
$ tpm2_load -C primary.ctx -c rsa.ctx -u rsa.pub -r rsa.priv

$ echo "meet me at.." >file.txt
$ tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt

$ cat sig.rss | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```


(or after reboot, reload the chain)
```bash
$ tpm2_createprimary -c primary.ctx
$ tpm2_load -C primary.ctx -c rsa.ctx -u rsa.pub -r rsa.priv
$ tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt
```

for other policy support within go-tpm-tools,  see [go-tpm-tools/issues/350](https://github.com/google/go-tpm-tools/issues/350)

#### Duplicate and transfer using endorsement key

- TPM-B

```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o primary.pub
tpm2_readpublic -c primary.ctx -o ek.pem -f PEM -Q


$ more ek.pem
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5oXTo399gxaBu7eaigVX
  eHkoT0rQqyBvL0ifC7gTMGqoXZprYH728klHbCZv90Sfmqznw0j8RjN6Lj5W6Fp1
  Oq6TrOeQX4En8s9bVvPFgUIjFE5xnZWgWdwsmftnYscvD9QP7LIHUs7E43fjUn3s
  ARui25kfbu+NYq9QqElQZjxwMtjWd+J3mG7Via8UZKOW1ny68SNeLkhlO44IBvWf
  kpDNRIjbKeDiM9x+HwFZGQ1eZMRfvLFLHmVwnA1iEZ3O5UmgapzxSpsk0tbxp3f9
  JFEF95/JQ2qM/OoOHnMA8m+Yv30Px+7jDWB8ZK58nsU8Hd/l5N/WrILH7Sp0gAXW
  MwIDAQAB
  -----END PUBLIC KEY-----

## copy primary.pub to tpm-a
```

- TPM-A

```bash
$ cat rsa.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwlmH3di2JpoBUtE6JKXthqPnS2tZXqFS302RuQavVFwZ7l7z
MbgAEvqzrF+JIhGr4LEVJwfNBbzOCNu+fT55Vq5/Pt3hCibb7/B2N4I4trfjdt2t
7+Kd8h4plMrszfY/gvK7MQBINe0spSAPWdnWkGXFY4emRbwo3NmjpLaSv0489LTD
gOA9uaPEk2dudrGyACWmbGMKm/2mxGVCuFIvtqW/Az/tpJ8mWVZZX4kmOlIIKZSd
ctF3wvyv1fTVwcmxfqGeFkN5WcSvUipZguRVNgLPBuYIMhC8+H+C1bw8FV+9TLs6
sHMSHp9GfwDQnkdnx4kInxhkD3/AT3B1gUZiKwIDAQABAoIBAQCMzH4A+7pi1tm0
nP2phUhCbcXoPro9M1StkC3NRQmKbTsgFUvMrkfneBbo/0GDHBhQLRps71raGEGP
61ris3sGkF6BNg+N4j8eYi/S4RWjUi+JcupLSvswaCepsyXBxO+YN6/jvReTceMR
MdvNNWMbs49AHwsXpExaS5Yhg19nFcxJd6MOfmFvJ9UimPh7XgSCtmrdQ0XKPoxG
7vWaNERN7xqgDyYG0oR2i+/4sDZ5KolehXNjmdDD/8qwa4PVEgVBn9QaypHNC1nD
njG39hIPvdN1Ix8kn7jtzuB0qePnQLC+87R4KAOXFNG3FGgUmDFVAIy7CSLcAJNG
G8yQy/GhAoGBAO/aXjBK6QnE19eDbm/mKzZB2+IVrdVe7cuORrqBlRrTf8NbqxtT
aIBd3kBfuGGLwuJLWLsyy1wc/rx0SZ/MOOWxk+/QQKhvp4dxn2imCBoNvozU6/Xg
I5Iawos6rwM8VGAcaaRa/atlGUpmSp5cVBl//HKAO5PyKS/PIxPjfaZxAoGBAM9u
9VoEx1yEK4cJDIX1KWIBCMq9lXBYv09WsLERKdfo4hMwbuv2CMMadvqPEh3h+dKr
4r7/cyrIyx4ydkRLBD1JC0yMUTMftqm5WBrImUvjpSNt8oV90R8VBDrfHzpRrFfj
9lEm0mKdl2Kn1R+Gu50aHNSwna+GhSjOgsHPK7hbAoGBALKaN6LcVTV6B4OqkfTv
PuQzHGn43K3S912pP0+oKICGV1AAlaROcrWLsHDdFi5E5USe+J7EzxtzV9i6+wvs
Bb48gj2EJHGIWwaHfD1vzP6hl2/FKUO4uKQWGyGT/Dh7lxTOc3f4bYZQTQnSq+PK
OrGWVURp6nNbUoIQSz2HG8xxAoGBAMAV7/28DyENA4G4T3B85iVq78lOZePzSrUd
geF2E1lsvm0mnJDE9Lg2+ZZshkpFyCHeKcrUosErz2vXLs1u6i4WRfBMv6Sn6W6h
w4SJ3er4kyOL3Njg+ZXe0Fvz4ecPWpjI8H+Vg5zuchFZeXIIQhPo6mnKYzr3RrfT
BCKUxdehAoGAA2lkBrhF/kw9i4bQ+ohOcIaU6cqF9PSlYKT/2LbP19C7O9Sld9rH
mdvDiyyIs7fXWnCuxPwl8PSjDCXbUrij2lQmgCndPWT8w2U22Y/E9xpGOwIQBd+P
YQJn9mZMKihGI5E381Oicx4jCBzpnGrVJ13j5rgyPmom6X55U6rwH3E=
-----END RSA PRIVATE KEY-----

echo "meet me at.." >file.txt
openssl dgst -sha256 -sign rsa.pem  file.txt | base64
  hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
  lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
  Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
  oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
  AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==



tpm2_startauthsession --policy-session -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat
tpm2_duplicate -U ek.pub -G rsa -k rsa.pem -u rsa.pub -r rsa.dpriv -s rsa.seed -L policy.dat  -p testpassword

## copy rsa.pub, rsa.dpriv, rsa.seed to tpm-b
```

- TPM-B

```bash

## ek uses  policysecret session https://github.com/tpm2-software/tpm2-tss/issues/2367#issuecomment-1147916014
tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement
tpm2 createek --ek-context ek.ctx

tpm2_import --parent-context ek.ctx  -G rsa -i rsa.dpriv -s rsa.seed -u rsa.pub -r rsa.priv --parent-auth session:session.ctx


tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

tpm2_load -C ek.ctx -c rsa.ctx -u rsa.pub -r rsa.priv --auth session:session.ctx

echo "meet me at.." >file.txt
tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt
  hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
  lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
  Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
  oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
  AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```



finally, since i was using a gce instance, i can use the api to get the EKPub KEY

```bash
$ gcloud compute instances get-shielded-identity instance-2 --format="value(encryptionKey.ekPub)"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5oXTo399gxaBu7eaigVX
eHkoT0rQqyBvL0ifC7gTMGqoXZprYH728klHbCZv90Sfmqznw0j8RjN6Lj5W6Fp1
Oq6TrOeQX4En8s9bVvPFgUIjFE5xnZWgWdwsmftnYscvD9QP7LIHUs7E43fjUn3s
ARui25kfbu+NYq9QqElQZjxwMtjWd+J3mG7Via8UZKOW1ny68SNeLkhlO44IBvWf
kpDNRIjbKeDiM9x+HwFZGQ1eZMRfvLFLHmVwnA1iEZ3O5UmgapzxSpsk0tbxp3f9
JFEF95/JQ2qM/OoOHnMA8m+Yv30Px+7jDWB8ZK58nsU8Hd/l5N/WrILH7Sp0gAXW
MwIDAQAB
-----END PUBLIC KEY-----
```

#### Duplicate an externally loaded HMAC key

- tpm-b

```bash
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_create  -C primary.ctx -g sha256 -G rsa \
-r new_parent.prv  -u new_parent.pub \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"
```

[cp new_parent.pub to tpm-a]

- tpm-a

```bash
export secret="change this password to a secret"
export plain="foo"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo -n $plain > data.in

tpm2 createprimary -Q -G rsa -g sha256 -C e -c primary.ctx

tpm2_startauthsession -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_flushcontext session.dat
rm session.dat

tpm2 import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv -L dpolicy.dat -a "sensitivedataorigin|userwithauth|sign"
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx
tpm2_readpublic -c hmac.ctx -o dup.pub

## test signature
echo -n "foo" | tpm2_hmac -g sha256 -c hmac.ctx | xxd -p -c 256

tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx
tpm2_duplicate -C new_parent.ctx -c hmac.ctx -G null  -p "session:session.dat" -r dup.dup -s dup.seed
```

[cp dup.pub, dup.dup, dup.seed to tpm-a]

- tpm-b

```bash
tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_flushcontext --transient-object
tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx

tpm2_import -C new_parent.ctx -u dup.pub -i dup.dup -r dup.prv -s dup.seed -L dpolicy.dat
tpm2_flushcontext --transient-object
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx

## test signature
echo -n "foo" | tpm2_hmac -g sha256 -c dup.ctx | xxd -p -c 256


## either persist dup.ctx to persistent handle or reload from scratch
# tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
# tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx
# tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx
```

## Author
@salrashid123
