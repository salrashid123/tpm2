## TPM2_DUPLICATE

see 

- [Prevent Chained duplication from A -> B -> C using tpm2_policyduplicationselect](https://gist.github.com/salrashid123/8cf62917392c3a05b4a750ce3cfe4c6a)

## Prevent Chained duplication from A -> B -> C using tpm2_policyduplicationselect

This procedure will transfer an HMAC key created inside TPM-A to TPM-B  but prevent TPM-B to transfer it to TPM-C.

Basically, and extension of As an end-to-end example, the following will transfer an RSA key generated on TPM-A to TPM-B but 
using `tpm2_policyduplicationselect` tp prevent further duplication

Step 1 below will transfer a key from A->B, step 2 attempts B->C but is prevented duplication on B by policy

- also see [Chained duplication from A -> B -> C tpm2_policycommandcode](https://gist.github.com/salrashid123/13166ff8d579d55436a128087d5b43c7)

---

### 1. Transfer A->B

#### B

```bash
## on B, first create a parent object
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_create  -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
    -u new_parent.pub -a "fixedtpm|fixedparent|restricted|sensitivedataorigin|decrypt|userwithauth"
```

_copy **new_parent.pub** to A_

#### A

```bash
## read the paren public part, load it and export its "name"
tpm2_print -t TPM2B_PUBLIC  new_parent.pub
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx -n dst_n.name

## create a primary object and a policy that that restricts duplicatoin to just `dst_n.name`
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_startauthsession -S session.dat
tpm2_policyduplicationselect -S session.dat  -N dst_n.name -L dpolicy.dat 
tpm2_flushcontext session.dat
rm session.dat

## create an hmac key with that policy
tpm2_create -C primary.ctx -g sha256 -G hmac -r key.prv -u key.pub  -L dpolicy.dat -a "sensitivedataorigin|userwithauth|sign"
tpm2_load -C primary.ctx -r key.prv -u key.pub -c key.ctx

## create a test hmac 
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c key.ctx | xxd -p -c 256
   42a1fad918fa0e4cbea94d759da89ccdfac5a640672d0170f4930cafe14d179c

### print the key  context and export the public part
tpm2_readpublic -c key.ctx -o dup.pub

## now start an auth session 
## bind the duplicate to the destination "name"
tpm2_startauthsession --policy-session -S session.dat
tpm2_readpublic -c key.ctx -n dupkey.name
tpm2_policyduplicationselect -S session.dat  -N dst_n.name -L dpolicy.dat  -n dupkey.name

## now duplicate 
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  -p "session:session.dat" -r dup.dup -s dup.seed
```

_copy **dup.dup dup.seed dup.pub** to B_

#### B

```bash
## reload the parent used for the transfer
tpm2_flushcontext --transient-object
tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx

## just import the duplicated key
tpm2_import -C new_parent.ctx -u dup.pub -i dup.dup  -r dup.prv -s dup.seed
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx

## test hmac 
## this will be the same as on A
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c dup.ctx | xxd -p -c 256
   42a1fad918fa0e4cbea94d759da89ccdfac5a640672d0170f4930cafe14d179c

tpm2_print -t TPM2B_PUBLIC  dup.pub 
```

---

### Transfer B-->C

Now try to tranfer the same key from B to C

#### C

```bash
## create a parent on C used for the transfer
tpm2_createprimary -C o -g sha256 -G rsa -c primary_2.ctx
tpm2_create  -C primary_2.ctx -g sha256 -G rsa -r new_parent_2.prv \
   -u new_parent_2.pub -a "fixedtpm|fixedparent|restricted|sensitivedataorigin|decrypt|userwithauth"
```

_ copy **new_parent_2.pub** to B_

#### B

```bash
## just as a sanity check load the **original** hmac key and check it
## remember this key was transfered from A->B using new_parent (new_parent_2 is from B->C)
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx

export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c dup.ctx | xxd -p -c 256


## load load new_parent_2 (which is the key from C)
tpm2_loadexternal -C o -u new_parent_2.pub -c new_parent_2.ctx -n dst_n.name
tpm2_startauthsession --policy-session -S session_2.dat
tpm2_readpublic -c dup.ctx -n dupkey.name

## set the policy duplicate against the "name" from C
tpm2_policyduplicationselect -S session_2.dat  -N dst_n.name -L dpolicy_2.dat  -n dupkey.name

## duplication will fail by policy 
### since the key is restricted to a parent
tpm2_duplicate -C new_parent_2.ctx -c dup.ctx -G null  -p "session:session_2.dat" -r dup_2.dup -s dup_2.seed


      WARNING:esys:src/tss2-esys/api/Esys_Duplicate.c:354:Esys_Duplicate_Finish() Received TPM Error 
      ERROR:esys:src/tss2-esys/api/Esys_Duplicate.c:116:Esys_Duplicate() Esys Finish ErrorCode (0x0000099d) 
      ERROR: Esys_Duplicate(0x99D) - tpm:session(1):a policy check failed
      ERROR: Unable to run tpm2_duplicate
```


---

- [Chained duplication from A -> B -> C tpm2_policycommandcode](https://gist.github.com/salrashid123/13166ff8d579d55436a128087d5b43c7)

## Chained duplication from  A -> B -> C  tpm2_policycommandcode 

This procedure will transfer an HMAC key created inside `TPM-A` to `TPM-B` and then to `TPM-C` using `tpm2_policycommandcode` 

Basically, and extension of  [As an end-to-end example, the following will transfer an RSA key generated on TPM-A to TPM-B](
https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md#example-2-as-an-end-to-end-example-the-following-will-transfer-an-rsa-key-generated-on-tpm-a-to-tpm-b)


To use this, you'll need three VMs.

Step 1 below will transfer a key from `A->B`, step 2 is `B->C`


### 1. Transfer A-->B

##### B

On VM-B, create parent object used for duplication

```bash
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_create  -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
   -u new_parent.pub -a "fixedtpm|fixedparent|restricted|sensitivedataorigin|decrypt|userwithauth"
```

_copy **new_parent.pub** to A_

#### A

```bash
## just print the public part 
tpm2_print -t TPM2B_PUBLIC  new_parent.pub

## create a tpm2_policycommandcode with TPM2_CC_Duplicate 
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_startauthsession -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_flushcontext session.dat
rm session.dat

## create the hmac key on the tpm with the policy
tpm2_create -C primary.ctx -g sha256 -G hmac -r key.prv -u key.pub \
   -L dpolicy.dat -a "sensitivedataorigin|userwithauth|sign"

## load and print the hmac key details
tpm2_load -C primary.ctx -r key.prv -u key.pub -c key.ctx
tpm2_readpublic -c key.ctx -n dupkey.name

## now hmac some data 
## (the output for you will be different)
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c key.ctx | xxd -p -c 256
   5bc1d93ea8b7a180877eeb754bf5f3bd84e94aa397b8ab5284dbd5dc823ff7c7

## now begin the duplication using the new_parent and the same policy
tpm2_readpublic -c key.ctx -o dup.pub
tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx -n dst_n.name
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  -p "session:session.dat" -r dup.dup -s dup.seed
```

_copy **dup.dup dup.seed dup.pub** to B_


#### B

```bash
## load the parent key used for duplication
tpm2_flushcontext --transient-object
tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx

## set the duplicate policy
tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate

## import and load the duplicated key
tpm2_import -C new_parent.ctx -u dup.pub -i dup.dup  -r dup.prv -s dup.seed -L dpolicy.dat
tpm2_flushcontext --transient-object
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx

## now run the hmac 
## (you'll see the same output as on A)
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c dup.ctx | xxd -p -c 256
   5bc1d93ea8b7a180877eeb754bf5f3bd84e94aa397b8ab5284dbd5dc823ff7c7
```

---

### Transfer B-->C

Repeate the same prodedure between B and C using the key loaded in the previous step

#### C

```bash
## create a parent for the transfer
tpm2_createprimary -C o -g sha256 -G rsa -c primary_2.ctx
tpm2_create  -C primary_2.ctx -g sha256 -G rsa -r new_parent_2.prv \
   -u new_parent_2.pub -a "fixedtpm|fixedparent|restricted|sensitivedataorigin|decrypt|userwithauth"
```

_ copy **new_parent_2.pub** to B_

#### B

```bash
## just to test, load the _original_ key sent a->b and run an hmac again
## this step isn't necessary but helps as a sanity check
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c dup.ctx | xxd -p -c 256

## print the public part of the parent from C
tpm2_print -t TPM2B_PUBLIC  new_parent_2.pub 

## start a duplicate session
tpm2_startauthsession -S session_2.dat --policy-session
tpm2_policycommandcode -S session_2.dat -L dpolicy_2.dat TPM2_CC_Duplicate
tpm2_flushcontext session_2.dat
rm session_2.dat

## again load the key sent from A
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx

## fulfill the policy for duplication
## load the parent from C
tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_loadexternal -C o -u new_parent_2.pub -c new_parent_2.ctx

## duplicate 
tpm2_duplicate -C new_parent_2.ctx -c dup.ctx -G null \
    -p "session:session.dat" -r dup_2.dup -s dup_2.seed
cp dup.pub dup_2.pub
```

_copy **dup_2.dup dup_2.seed dup_2.pub** to C_

#### C

```bash
## load the original parent from C
tpm2_flushcontext --transient-object
tpm2_load -C primary_2.ctx -u new_parent_2.pub -r new_parent_2.prv -c new_parent_2.ctx

## start the policy
tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate

## import the duplicated key
tpm2_import -C new_parent_2.ctx -u dup_2.pub -i dup_2.dup  -r dup_2.prv -s dup_2.seed -L dpolicy.dat
tpm2_flushcontext --transient-object
tpm2_load -C new_parent_2.ctx -u dup_2.pub -r dup_2.prv -c dup_2.ctx

## test with hmac
## you'll see the same hmac output
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c dup_2.ctx | xxd -p -c 256
  5bc1d93ea8b7a180877eeb754bf5f3bd84e94aa397b8ab5284dbd5dc823ff7c7
```


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

securely copy a HMAC key from one TPM to another

- `tpm-b`

```bash
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_create  -C primary.ctx -g sha256 -G rsa \
-r new_parent.prv  -u new_parent.pub \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"
```

[cp new_parent.pub to tpm-a]

- `tpm-a`

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
echo -n  $plain | tpm2_hmac -g sha256 -c hmac.ctx | xxd -p -c 256

tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx
tpm2_duplicate -C new_parent.ctx -c hmac.ctx -G null  -p "session:session.dat" -r dup.dup -s dup.seed
```

[cp `dup.pub`, `dup.dup`, `dup.seed` to tpm-b]

- `tpm-b`

```bash
tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
tpm2_flushcontext --transient-object
tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx

tpm2_import -C new_parent.ctx -u dup.pub -i dup.dup -r dup.prv -s dup.seed -L dpolicy.dat
tpm2_flushcontext --transient-object
tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx

## test signature
export plain="foo"
echo -n $plain | tpm2_hmac -g sha256 -c dup.ctx | xxd -p -c 256
## you should see the same as in TPM-A

## for peristent use, either persist dup.ctx to a non-transient handle
#  tpm2_evictcontrol -C o -c dup.ctx 0x81008001
## or reload the entire chain from scratch
# tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
# tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx
# tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx
```

## Author
@salrashid123
