## Using Policies to RSA Signatures and AES Encrypt/Decrypt


i'm using the swtpm here:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  &&    sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert &&  sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
```

## No Policy

```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_createprimary -C o -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx
tpm2_encryptdecrypt -Q --iv iv.bin -c aes.ctx -o cipher.out secret.dat
tpm2_encryptdecrypt -Q --iv iv.bin -c aes.ctx -d -o plain.out cipher.out
```

## Password without policy


```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_createprimary -C o -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx  -p testpswd
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -o cipher.out -p testpswd  secret.dat
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -d -o plain.out -p testpswd cipher.out
```

With Session

```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat -p testpswd
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx


tpm2_startauthsession --policy-session -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out -p"session:session.dat+testpswd"  secret.dat
tpm2_flushcontext session.dat


tpm2_startauthsession --policy-session -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out -p"session:session.dat+testpswd" cipher.out
tpm2_flushcontext session.dat
```

### sign with session

```bash
tpm2_evictcontrol -C o -c 0x81008001

tpm2_pcrread sha256:23

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat


tpm2_createprimary -C o -c primary.ctx
tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa.pub -r rsa.priv -C primary.ctx  -L policy.dat -p testpswd
tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx
tpm2_evictcontrol -C o -c rsa.ctx 0x81008001


tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx

echo "my message" > message.dat
tpm2_sign -c rsa.ctx -g sha256 -o sig.ecc message.dat  -p"session:session.dat+testpswd"
tpm2_verifysignature -c rsa.ctx -g sha256 -s sig.ecc -m message.dat

tpm2_flushcontext session.dat

tpm2_dictionarylockout --setup-parameters --max-tries=4294967295 --clear-lockout
```
## PCR

```bash
## policy pcr
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha1 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out   secret.dat  -p"pcr:sha256:23=pcr23_val.bin"
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p"pcr:sha256:23=pcr23_val.bin"


## with session
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l "sha256:0,23"  -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C o -l "sha256:0,23" -g sha256 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes128cfb -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

tpm2_startauthsession --policy-session --session=session.dat
tpm2_policypcr --session=session.dat --pcr-list="sha256:0,23"
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out   secret.dat  --auth=session:session.dat
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session --session=session.dat
tpm2_policypcr --session=session.dat --pcr-list="sha256:0,23"
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out --auth=session:session.dat
tpm2_flushcontext session.dat

cat plain.out

## or with session with pcr and password policy  policyHash = 57689d20acc2066a79fb75da85c049b4c332ffeeff1f84f67f8e6bd815b4c994
## Encrypt/Decrypt

echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx  -L policy.dat -p testpswd
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx  


tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23 -f pcr23_val.bin
tpm2_policypassword -S session.dat -L policy.dat 
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out   secret.dat  -p"session:session.dat+testpswd"
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l sha256:23
tpm2_policypassword -S session.dat -L policy.dat 
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p"session:session.dat+testpswd"
tpm2_flushcontext session.dat


tpm2_pcrread sha256:23
tpm2_pcrextend  23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23
    sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
tpm2_pcrextend  23:sha256=0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```


## Seal/Unseal

```bash
tpm2_startauthsession -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
echo "my sealed data" > seal.dat
tpm2_create -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat -p testpswd -i seal.dat
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx  

tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23 -f pcr23_val.bin
tpm2_policypassword -S session.dat -L policy.dat 

tpm2_unseal -o unseal.dat -c key.ctx -p"session:session.dat+testpswd"
```

### Policy Signed

- [https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf)


```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx

echo "foo" > secret.dat

tpm2_startauthsession -S session.ctx
tpm2_policysigned -S session.ctx -f rsassa -g sha256 -c signing_key.ctx -L policy.dat
tpm2_flushcontext session.ctx
tpm2_createprimary -C o -c primary.ctx -Q
tpm2_create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx -C primary.ctx -i secret.dat -L policy.dat -Q
## Unseal secret
tpm2_startauthsession -S session.ctx --policy-session
### Generate signature
tpm2_policysigned -S session.ctx -c signing_key.ctx -x --raw-data to_sign.bin -x -t 3
### Sign the candidate
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
###Satisfy the policy

## to test failure, expire the time constraint (tpm:parameter(4):the policy has expired)
# sleep 4
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa -c signing_key.ctx -x -t 3
tpm2_unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat
tpm2_flushcontext session.ctx
cat unsealed.dat
```


policy signed for AES:

```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx


tpm2_startauthsession -S session.ctx
tpm2_policysigned -S session.ctx -f rsassa -g sha256 -c signing_key.ctx -L policy.dat
tpm2_flushcontext session.ctx
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx -Q
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

tpm2_startauthsession -S session.ctx --policy-session
tpm2_policysigned -S session.ctx -c signing_key.ctx -x --raw-data to_sign.bin -x -t 3
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa -c signing_key.ctx -x -t 3

tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out -p"session:session.ctx"  secret.dat
tpm2_flushcontext session.ctx


tpm2_startauthsession -S session.ctx --policy-session
tpm2_policysigned -S session.ctx -c signing_key.ctx -x --raw-data to_sign.bin -x -t 3
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa -c signing_key.ctx -x -t 3
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p "session:session.ctx"
tpm2_flushcontext session.ctx
cat plain.out
```

- policy signed for AES with cphash and manual signature


```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
echo "foo" > secret.dat
openssl rand  -out iv.bin 16
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx

tpm2_startauthsession -S session.ctx
tpm2_policysigned -S session.ctx -f rsassa -g sha256 -c signing_key.ctx -L policy.dat  -q 98ba3a
tpm2_flushcontext session.ctx
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l


tpm2_startauthsession -S session.ctx --policy-session
tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx  --cphash=cphash.bin   secret.dat

tpm2_policysigned -S session.ctx -c signing_key.ctx --cphash=cphash.bin --raw-data to_sign.bin -x -t 30 -q 98ba3a

# $ xxd -p -c 100 cphash.bin 
# 002090c4f6cd86c4f793dff3709fcd2542baa2b7c90d42de12c3666fc298cea8830d
#    .> remove the 0020 prefix for the actual hash
# $ xxd -p -c 100 cphash.bin 
#    0020 d27d7d6d4f84d65d3477322053424d3dfda16105c9c146ccafb906b89d60b44e

## so the segmented signature is "to_sign.bin":
# xxd -p -c 100 to_sign.bin
# a0914fa8287e4decd2299f77bb3ad986d957368e4c595a205d68d8b744a890fb 0000001e d27d7d6d4f84d65d3477322053424d3dfda16105c9c146ccafb906b89d60b44e 98ba3a

### to generate it manually:
### note tpm2_startauthsession does not return the nonce used after commit https://github.com/tpm2-software/tpm2-tools/commit/bbe177f7248e988b6d155c01bc08dcba8aaead3d
###  which means i don't know how to get this bit; i do know go-tpm allows for it https://pkg.go.dev/github.com/google/go-tpm/tpm2#StartAuthSessionResponse

# export NONCE="a0914fa8287e4decd2299f77bb3ad986d957368e4c595a205d68d8b744a890fb"
# export EXPIRYTIME="0000001e"  # 30
# export CPHASH="d27d7d6d4f84d65d3477322053424d3dfda16105c9c146ccafb906b89d60b44e"
# export QUALIFICATION="98ba3a"

# echo -n $NONCE$EXPIRYTIME$CPHASH$QUALIFICATION | xxd -r -p | openssl dgst -sha256 -sign private.pem -out signature.dat

# $ echo -n $NONCE$EXPIRYTIME$CPHASH$QUALIFICATION | xxd -r -p |  sha256sum
# 39f05dc65a2dbf647d77047dba302586c569ef60bdb9b02f30f7aec986665a43  -
# $ sha256sum to_sign.bin 
# 39f05dc65a2dbf647d77047dba302586c569ef60bdb9b02f30f7aec986665a43  to_sign.bin

#tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin

tpm2_policysigned -S session.ctx -g sha256 -s signature.dat --cphash=cphash.bin -f rsassa -c signing_key.ctx -x -t 30 -q 98ba3a
tpm2_flushcontext -t
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out -p"session:session.ctx"  secret.dat
tpm2_flushcontext session.ctx
```

Signed policy data

```bash
# ## no restrictions
$ tpm2_policysigned -S session.ctx -c signing_key.ctx  --raw-data to_sign.bin 
$ xxd -p -c 100 to_sign.bin 
   00000000

# ## with qualification
$ tpm2_policysigned -S session.ctx -c signing_key.ctx  --raw-data to_sign.bin  -q 98ba3a
$ xxd -p -c 100 to_sign.bin 
   0000000098ba3a

# ## with qualification and timeout
$ tpm2_policysigned -S session.ctx -c signing_key.ctx  --raw-data to_sign.bin -t 30 -q 98ba3a
$ xxd -p -c 100 to_sign.bin 
   0000001e 98ba3a

# ## with cphash, qualification and timeout
$ tpm2_encryptdecrypt  --iv iv.bin  -c aes.ctx  --cphash=cphash.bin   secret.dat
$ xxd -p -c 100 cphash.bin 
   0020 ad8bb4d5ee390d3e665bd00f3a5347050b1df66ba195ba2a5adf4fc2758acea9   ## remove prefix 0020
$ tpm2_policysigned -S session.ctx -c signing_key.ctx --cphash=cphash.bin --raw-data to_sign.bin  -t 30 -q 98ba3a
$ xxd -p -c 100 to_sign.bin 
   0000001e ad8bb4d5ee390d3e665bd00f3a5347050b1df66ba195ba2a5adf4fc2758acea9 98ba3a

# ## with nonce, timeout, cphash and qualification
$ tpm2_policysigned -S session.ctx -c signing_key.ctx --cphash=cphash.bin --raw-data to_sign.bin -x -t 30 -q 98ba3a
$ xxd -p -c 100 to_sign.bin 
   59868e09919e21fb9a041e1cafaba9ac95d45967bac24e1ee9670be29310f213 0000001e ad8bb4d5ee390d3e665bd00f3a5347050b1df66ba195ba2a5adf4fc2758acea9 98ba3a
```
