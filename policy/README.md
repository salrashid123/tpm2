## Using Policies to AES Encrypt/Decrypt

## No Policy

```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_createprimary -C e -g sha1 -G rsa -c primary.ctx
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
tpm2_policysigned -S session.ctx -c signing_key.ctx -L policy.signed -x -t 3
tpm2_flushcontext session.ctx
tpm2_createprimary -C o -c prim.ctx -Q
tpm2_create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx -C prim.ctx -i secret.dat -L policy.signed -Q
## Unseal secret
tpm2_startauthsession -S session.ctx --policy-session
### Generate signature
tpm2_policysigned -S session.ctx -c signing_key.ctx -x --raw-data to_sign.bin -x -t 3
openssl dgst -sha256 -sign private.pem -out signature.dat to_sign.bin
###Satisfy the policy

## to test, expire the time constraint
#sleep 4
tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa -c signing_key.ctx -x -t 3
tpm2_unseal -p session:session.ctx -c sealing_key.ctx -o unsealed.dat
tpm2_flushcontext session.ctx
```


















