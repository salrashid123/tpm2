snippet on transferring an rsa key from one  VM to another using the remote's endorsement key

eg, transfer rsa key from `laptop --> instance-2's TPM`

with 

* [tpm2_duplicate](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate)

then reboot instance-2 and reload the context

* [reloading context chaings](https://github.com/salrashid123/tpm2/tree/master/context_chain)


### instance-2

first create the endorsement key on isntance-2, print its public key

```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o ek.pem -f PEM -Q

cat ek.pem
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

### on laptop

copy the `ek.pub` to instance-1

```bash
gcloud compute scp instance-2:ek.pub .
```

Note, in my case, the `ek.pub` is `TPM2B_PUBLIC` format (not PEM but you can extract the details too from there)

```
$ tpm2_print -t TPM2B_PUBLIC ek.pub 
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt
  raw: 0x300b2
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
rsa: e685d3a37f7d831681bbb79a8a05577879284f4ad0ab206f2f489f0bb813306aa85d9a6b607ef6f249476c266ff7449f9aace7c348fc46337a2e3e56e85a753aae93ace7905f8127f2cf5b56f3c5814223144e719d95a059dc2c99fb6762c72f0fd40fecb20752cec4e377e3527dec011ba2db991f6eef8d62af50a84950663c7032d8d677e277986ed589af1464a396d67cbaf1235e2e48653b8e0806f59f9290cd4488db29e0e233dc7e1f0159190d5e64c45fbcb14b1e65709c0d62119dcee549a06a9cf14a9b24d2d6f1a777fd245105f79fc9436a8cfcea0e1e7300f26f98bf7d0fc7eee30d607c64ae7c9ec53c1ddfe5e4dfd6ac82c7ed2a748005d633
authorization policy: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
```


```bash
$ tpm2_print -t TPM2B_PUBLIC ek.pub  -f pem
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

fwiw, on Google Cloud shielded VMs, you have an API to remotely read the ek too

```bash
$ gcloud compute instances get-shielded-identity instance-2
encryptionKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5oXTo399gxaBu7eaigVX
    eHkoT0rQqyBvL0ifC7gTMGqoXZprYH728klHbCZv90Sfmqznw0j8RjN6Lj5W6Fp1
    Oq6TrOeQX4En8s9bVvPFgUIjFE5xnZWgWdwsmftnYscvD9QP7LIHUs7E43fjUn3s
    ARui25kfbu+NYq9QqElQZjxwMtjWd+J3mG7Via8UZKOW1ny68SNeLkhlO44IBvWf
    kpDNRIjbKeDiM9x+HwFZGQ1eZMRfvLFLHmVwnA1iEZ3O5UmgapzxSpsk0tbxp3f9
    JFEF95/JQ2qM/OoOHnMA8m+Yv30Px+7jDWB8ZK58nsU8Hd/l5N/WrILH7Sp0gAXW
    MwIDAQAB
    -----END PUBLIC KEY-----
kind: compute#shieldedInstanceIdentity
signingKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolr1s4pfb14Hzi84sQ+0
    Z5/t4umiRUzVeMSdnyuDxAV+YL+bhYe7/wiUFNOpIVkN/Mvb+tzSQPnNRIo5xbZ4
    VdlPvnMdpriy4oMLB0Ulou/o9yWbi4PXjtne+E6CgF1/0DthbgIkgLl1eqiPzcV/
    TuqqIUSvYhjzw5OiNDHCkfjCcRUlAktYL4za3kMzKzEK2dgyTxWbzrz40tE4f8Fy
    ePC/vCzDRwvpPeQ/2Wr3s/tCHkyeYeUrZ6Fr1Gpam8e2SeYTE++1aBP/uIU4B0ge
    id7mCGX2uu6tim5swHBD5zHTH/ISnbn8Dh8eJUyxTvzmR8o7ZgoDFr27RdefZTbP
    uwIDAQAB
    -----END PUBLIC KEY-----
```

### instance-1

anyway assume this is the rsa key on `instance-1` we want to transfer 

```bash
cat rsa.pem
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
```

just make any signature which we'll use later to confirm the transfer

```bash
echo "meet me at.." >file.txt
openssl dgst -sha256 -sign rsa.pem  file.txt | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```


```bash
tpm2_startauthsession --policy-session -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat
tpm2_duplicate -U ek.pub -G rsa -k rsa.pem -u rsa.pub -r rsa.dpriv -s rsa.seed -L policy.dat  -p testpassword
```

### on laptop

copy the generated objects `rsa.pub`, `rsa.dpriv`, `rsa.seed` to `instance-2`

```bash
gcloud compute scp rsa.pub instance-2:
gcloud compute scp rsa.dpriv instance-2:
gcloud compute scp rsa.seed instance-2:
```

### instance-2

load the remote context into the TPM and verify the signature

```bash
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

cat sig.rss  | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```

---


[reboot instance-2]

### instance-2

Reload the key context [https://github.com/salrashid123/tpm2/tree/master/context_chain](https://github.com/salrashid123/tpm2/tree/master/context_chain)

```bash
tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

$ ls
rsa.priv  rsa.pub


tpm2 createek --ek-context ek.ctx
tpm2_load -C ek.ctx -c rsa.ctx -u rsa.pub -r rsa.priv --auth session:session.ctx

echo "meet me at.." >file.txt
tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt

cat sig.rss  | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```