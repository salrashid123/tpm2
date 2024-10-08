
list persistent handles

```bash
# tpm2_getcap handles-persistent
- 0x81008000
```

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

3) NV with PCR policy 

```bash
tpm2_pcrread -o measured.pcrvalues sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

tpm2_createpolicy --policy-pcr -l sha256:23 -f measured.pcrvalues -L measured.policy

tpm2_nvdefine 0x1500016 -C o -s 32 -L measured.policy -a "policyread|policywrite"

echo -n "fooo secret" > secret.txt

tpm2_nvwrite 0x1500016 -C 0x1500016 -P pcr:sha256:23=measured.pcrvalues -i secret.txt
tpm2_nvread 0x1500016 -C 0x1500016 -P pcr:sha256:23=measured.pcrvalues
```

4) Read EKCert RSA from NV

from pg 13 of [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf)

```
2.2.1.4 Low Range
The Low Range is at NV Indices 0x01c00002 - 0x01c0000c.
0x01c00002 RSA 2048 EK Certificate
0x01c00003 RSA 2048 EK Nonce
0x01c00004 RSA 2048 EK Template
0x01c0000a ECC NIST P256 EK Certificate
0x01c0000b ECC NIST P256 EK Nonce
0x01c0000c ECC NIST P256 EK Template
```

Note, omit the `0` prefix

```bash
export TPM2_EK_NV_INDEX=0x1c00002
tpm2_nvreadpublic | sed -n -e "/""$TPM2_EK_NV_INDEX""/,\$p" | sed -e '/^[ \r\n\t]*$/,$d' | grep "size" | sed 's/.*size.*://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]$//'
# the ouput data size will be diferent


tpm2_nvread -s 1422  -C o $TPM2_EK_NV_INDEX |  openssl x509 --inform DER -text -noout  -in -
```



===============

5) Write and Read from NV

```bash
go run nv_basic/main.go
```

6) Read NV as buffers



```bash
#### constants at: https://pkg.go.dev/github.com/google/go-tpm-tools/client#pkg-constants

# gcloud compute instances create instance-1 \
#     --zone=us-central1-a \
#     --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan" \
#     --shielded-secure-boot --no-service-account --no-scopes \
#     --shielded-vtpm \
#     --shielded-integrity-monitoring \
#     --confidential-compute


# $  gcloud compute instances get-shielded-identity  instance-1


# TPM2_EK_NV_INDEX=0x1c10000
# tpm2_nvreadpublic | sed -n -e "/""$TPM2_EK_NV_INDEX""/,\$p" | sed -e '/^[ \r\n\t]*$/,$d' | grep "size" | sed 's/.*size.*://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]$//'
#  1516
# tpm2_nvread -s 1516  -C o $TPM2_EK_NV_INDEX |  openssl x509 --inform DER -text -noout  -in -


go run nv_buffer/main.go
```