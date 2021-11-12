
https://github.com/tpm2-software/tpm2-tools/blob/master/test/integration/tests/nv.sh

```bash
1) BASIC
tpm2_nvundefine -C o 1
tpm2 nvdefine  1 -C o -s 12 -a "ownerread|ownerwrite"
echo -n "please123abc" > nv.test_w
tpm2_nvreadpublic 
tpm2 nvwrite -Q   1 -C o -i nv.test_w
tpm2 nvread  1 -C o -s 12 | xxd  -
```

2) Policy written to NV
https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policyauthorizenv.1.md

```bash
tpm2_nvundefine -C o 1
tpm2_nvdefine -C o  -a "authread|authwrite" -s 34 1

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

echo "000b" | xxd -p -r | cat - policy.dat | tpm2_nvwrite -C 1  1  -i  -

tpm2_startauthsession -S session.ctx
tpm2_policyauthorizenv -S session.ctx -C 1  -L policyauthorizenv.dat 1
tpm2_flushcontext session.ctx

tpm2_createprimary -C o -c prim.ctx
echo "secretdata" | tpm2_create -C prim.ctx -u key.pub -r key.priv -a "fixedtpm|fixedparent|adminwithpolicy" -L policyauthorizenv.dat -i -

tpm2_load -C prim.ctx -u key.pub -r key.priv -c key.ctx
tpm2_pcrread sha256:23 -o pcr23_val.bin

tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypcr -S session.ctx -l sha256:23 -f pcr23_val.bin
tpm2_policyauthorizenv -S session.ctx -C 1  1

tpm2_unseal -c key.ctx -p session:session.ctx
tpm2_flushcontext session.ctx
```

3) Read EKCert RSA from NV

```bash
export TPM2_EK_NV_INDEX=0x1c00002
tpm2_nvreadpublic | sed -n -e "/""$TPM2_EK_NV_INDEX""/,\$p" | sed -e '/^[ \r\n\t]*$/,$d' | grep "size" | sed 's/.*size.*://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]$//'


tpm2_nvread -s 1335  -C o $TPM2_EK_NV_INDEX |  openssl x509 --inform DER -text -noout  -in -
```




