## generate various keys types using tpm2_tools

see: https://github.com/tpm2-software/tpm2-tools/issues/3545#event-22506138197


for the srk:

* [7.5.1 Storage Primary Key (SRK) Templates:](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)

applied that override to
 
* [ B.3.4 Template L-2: ECC NIST P256 (Storage)](https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf)


#### RSAEK

```bash
tpm2_createek -c primary.ctx -G rsa -Q
tpm2_readpublic -c primary.ctx -o rsa_eek.pem -f PEM -Q
tpm2_flushcontext -t
```

#### ECCEK

```bash
tpm2_createek -c primary.ctx -G ecc -Q
tpm2_readpublic -c primary.ctx -o ecc_eek.pem -f PEM -Q
tpm2_flushcontext -t
```

#### RSASRK

```bash
tpm2_flushcontext -t
printf '\x00\x01' > ud.1
dd if=/dev/zero bs=256 count=1 of=ud.2
cat ud.1 ud.2 > unique.dat
tpm2_createprimary -C o  -u unique.dat \
     -G rsa2048  -g sha256  -c primary.ctx --attributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"
tpm2_readpublic -c primary.ctx -o rsa_srk.pem -f PEM -Q
tpm2_flushcontext -t
```


#### ECCSRK

```bash
$ printf '\x20\x00' > ud.1

$ dd if=/dev/zero bs=128 count=1  of=ud.2

$ cat ud.1 ud.2 ud.1 ud.2 > unique.dat

$ tpm2_createprimary -C o -G ecc256 -g sha256 -c primary.ctx  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat 

$ tpm2_readpublic -c primary.ctx -o ecc_srk.pem -f PEM -Q

$ cat ecc_srk.pem 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESTbI+P+fejonjMYWJVtQdLTPh9BP
ZJf6d7YjLW60ALjmVOkXoskpURGdAP6TN5da9zbNtDMawGZL85gKxkHqEA==
-----END PUBLIC KEY-----
```