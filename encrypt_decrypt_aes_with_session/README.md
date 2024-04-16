

```bash
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_policypcr -S session.dat -l "sha256:0,23"  -L policy.dat
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx -p foo
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat -P foo -p bar
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx --auth="foo"

tpm2_startauthsession --policy-session --session=session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_policypcr --session=session.dat --pcr-list="sha256:0,23"
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out   secret.dat  --auth="session:session.dat+bar"
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session --session=session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_policypcr --session=session.dat --pcr-list="sha256:0,23"
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out --auth="session:session.dat+bar"
tpm2_flushcontext session.dat
```

