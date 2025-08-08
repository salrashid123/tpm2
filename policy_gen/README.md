
### Reconstruct Policy using command parameters

Sample which reconstructs a known policy using raw command parameters:

The usecase for this is to regenerate a policy using just the command parameters as described in [TPMPolicy Syntax](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-4.1)

For example, the following PEM TPM key uses a PCR policy (code `tpm2.TPMCCPolicyPCR 017F` and `tpm2.TPMCCPolicyAuthValue 016B`)

The `tpm2.TPMCCPolicyPCR` command parameters are described in [23.7 TPM2_PolicyPCR](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf) and is basically a concat of `TPM2B_DIGEST` with `TPML_PCR_SELECTION`

The structure below shows the encoded parameters for a PEM TPM key which has both PCR and PolicyAuthValue: 

```bash
$ cat private.pem 
-----BEGIN TSS2 PRIVATE KEY-----
MIICdwYGZ4EFCgEDoUYwRDA2oAQCAgF/oS4ELAAg4vYcP3HR3v0/qZnfo2lTdVxp
Bol5mWK0i+vYNpdOjPkAAAABAAsDAACAMAqgBAICAWuhAgQAAgRAAAABBIIBOgE4
AAEACwAEAHIAIDTiKp2k1c5wQVDv/Wf7aZTVz6Gm4qBKpFFAk/D00xnQABAAFAAL
CAAAAQABAQCsgvEU2ZGQNxfEypDU0TAXvaTxl3cUzRjU4RTr5vIJUILUpsB5gGtB
WAzT/9fMYcq5vO6oImt6/vIlhPnyHNXrkSHW9f3uOg6Pj8fXBzCl1X4YCHcn6VG1
JrE5NR41TSwgnDG7Y1o8NRXCVo+KbKiYD/Mv2R4qZUKNgIL62VfDSy1B3QoxJWHv
5BFHKFx9ENkaiU0Cs97wuxVb+qsPV4Tq57K3gi3NvHW2nrLun5aPg6JzHRo7Bt7g
f3qWE+8eNfO0UZcA6fxOoQLcHyGTxMReBkzTm/he/BLyfMdotYyu2jehUuUpoaZ0
XrQtPrluxogLk30P5u+9Mcud3ade0jSbBIHgAN4AIK3f+hAg2xs7t1/rhf9tvXpj
p+3UMKRes8WlABEebnIHABBbv2yNzogHpRtejGqw5H7PqhKU7rNoSf7dqTEXeOzS
LMlr6nSapSZqO/8yu8LMCcG4euNcmrgcuw3Ctx9hlqO4A/QwxCsS4Wn5fpgQuPuD
0fO2dk1VXlt1jbXXaAoRArZ1UsvuJTZxTeDK3CxVVD4kfYLygaZigDLz4dT1SbK/
kU6pMoobhvKS6Mjw0uU3pseNH/0PEAIRBIsFe1O5jDrMbBq578z5ko7oKnpa2CMR
9rZ6PguH9mF8dgI=
-----END TSS2 PRIVATE KEY-----


## which when decoded:

$ openssl asn1parse -inform PEM -in private.pem
    0:d=0  hl=4 l= 631 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=  70 cons: cont [ 1 ]        
   14:d=2  hl=2 l=  68 cons: SEQUENCE          
   16:d=3  hl=2 l=  54 cons: SEQUENCE          
   18:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   20:d=5  hl=2 l=   2 prim: INTEGER           :017F
   24:d=4  hl=2 l=  46 cons: cont [ 1 ]        
   26:d=5  hl=2 l=  44 prim: OCTET STRING      [HEX DUMP]:0020E2F61C3F71D1DEFD3FA999DFA36953755C690689799962B48BEBD836974E8CF900000001000B03000080
   72:d=3  hl=2 l=  10 cons: SEQUENCE          
   74:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   76:d=5  hl=2 l=   2 prim: INTEGER           :016B
   80:d=4  hl=2 l=   2 cons: cont [ 1 ]        
   82:d=5  hl=2 l=   0 prim: OCTET STRING      
   84:d=1  hl=2 l=   4 prim: INTEGER           :40000001
   90:d=1  hl=4 l= 314 prim: OCTET STRING      [HEX DUMP]:01380001000B00040072002034E22A9DA4D5CE704150EFFD67FB6994D5CFA1A6E2A04AA4514093F0F4D319D000100014000B0800000100010100AC82F114D991903717C4CA90D4D13017BDA4F1977714CD18D4E114EBE6F2095082D4A6C079806B41580CD3FFD7CC61CAB9BCEEA8226B7AFEF22584F9F21CD5EB9121D6F5FDEE3A0E8F8FC7D70730A5D57E18087727E951B526B139351E354D2C209C31BB635A3C3515C2568F8A6CA8980FF32FD91E2A65428D8082FAD957C34B2D41DD0A312561EFE41147285C7D10D91A894D02B3DEF0BB155BFAAB0F5784EAE7B2B7822DCDBC75B69EB2EE9F968F83A2731D1A3B06DEE07F7A9613EF1E35F3B4519700E9FC4EA102DC1F2193C4C45E064CD39BF85EFC12F27CC768B58CAEDA37A152E529A1A6745EB42D3EB96EC6880B937D0FE6EFBD31CB9DDDA75ED2349B
  408:d=1  hl=3 l= 224 prim: OCTET STRING      [HEX DUMP]:00DE0020ADDFFA1020DB1B3BB75FEB85FF6DBD7A63A7EDD430A45EB3C5A500111E6E720700105BBF6C8DCE8807A51B5E8C6AB0E47ECFAA1294EEB36849FEDDA9311778ECD22CC96BEA749AA5266A3BFF32BBC2CC09C1B87AE35C9AB81CBB0DC2B71F6196A3B803F430C42B12E169F97E9810B8FB83D1F3B6764D555E5B758DB5D7680A1102B67552CBEE2536714DE0CADC2C55543E247D82F281A6628032F3E1D4F549B2BF914EA9328A1B86F292E8C8F0D2E537A6C78D1FFD0F100211048B057B53B98C3ACC6C1AB9EFCCF9928EE82A7A5AD82311F6B67A3E0B87F6617C7602

```


### Direct

so given that  `0020E2F61C3F71D1DEFD3FA999DFA36953755C690689799962B48BEBD836974E8CF900000001000B03000080` represents the PCRPolicy parameters, to convert that to go-tpm `PolicyPCR`

```golang
	// TPM2BDigest struct section 10.4.2 https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
	//    size UINT16
	//    buffer[size]{:sizeof(TPMU_HA)} BYTE

	// get the length of the digest, first 2bytes is length of buffer
	commandParameter := "0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080"

	l := binary.BigEndian.Uint16(commandParameter[:2])
	dgst := commandParameter[:l+2]

	d, err := tpm2.Unmarshal[tpm2.TPM2BDigest](dgst)
	t, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](commandParameter[l+2:])

	_, err = tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
		PcrDigest:     *d,
		Pcrs:          *t,
	}.Execute(rwr)
```

see `policy_pcr_direct/pcrgen.go` which reconstructs the policy by hand:

to setu

to setup, run:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5


## new window 

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/ 
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23



echo "foo" > secret.dat
openssl rand  -out iv.bin 16


tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_flushcontext session.dat


printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx


tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23"  -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out -p"session:session.dat"  secret.dat
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23"  -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p"session:session.dat"
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l


tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o private.pem

openssl asn1parse -inform PEM -in private.pem
```

---

### By Reflection 

The `_util*` examples here demonstrates how to use [tpm2genkey/util](https://github.com/salrashid123/tpm2genkey?tab=readme-ov-file#policy-command-parameters) library 
to convert between the wire bytes for the PEM encoding and actual structures:

* `policy_pcr_util/` : Regenerate policy PCR using the utility
* `policy_pcr_direct`: Regenerate policy PCR manually
* `policy_secret_util/` : Regenerate policy Secret using the utility
* `policy_signed_util/`: Regenerate PolicySigned
* `policy_authorize_direct/`: Regenerate PolicyAuthorize manually 
* `policy_authorize_util/`: Regenerate PolicyAuthorize using the utility 


for end to end example, see [tpmcopy: TPMPolicy Syntax PEM Encoding](https://github.com/salrashid123/tpmcopy?tab=readme-ov-file#tpmpolicy-syntax-pem-encoding)

---

#### PolicyPCR

```log
$ go run policy_pcr_util/pcrgen.go 
2024/12/20 07:20:31 PolicyPCR CPBytes 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
2024/12/20 07:20:31 pcrSelectionSegment 00000001000b03000080
2024/12/20 07:20:31 pcrDigestSegment 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9
2024/12/20 07:20:31 commandParameter 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
2024/12/20 07:20:31 IV: 27641433d56ae667cb188a8c9315a7db
2024/12/20 07:20:31 Encrypted 2892d0f02c
```

#### PolicySecret

```log
$ go run policy_secret_util/secretgen.go 
2024/12/20 07:21:08 ======= createPrimary ========
2024/12/20 07:21:08 ======= create ========
2024/12/20 07:21:08 PolicySecret Bytes: 4000000b00044000000b
2024/12/20 07:21:08 IV: 9216bafdc6e74ebc9cb580d2f3c3f4e8
2024/12/20 07:21:08 Encrypted 61eeead96f
2024/12/20 07:21:08 Decrypted foooo
```

#### PolicyAuthorize:

```log
$ go run policy_authorize_util/authorizegen.go 
2024/12/20 07:17:12 Public 
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4FJVQw2iQzO5E9/H5zs97OaIlhVfVc18zVQkLq6rC177uLrnhxjf
qh62ktFBDgVRvWTEjkLUBEBmQZf13RUmjG4PWK2kZ5O2hNj63v1afvkM1gFttVuH
lX+YF3kAZMziM2/oDLlPwLyiWp1N5suGjs6l+83GiASIyYe6JIZHqR0Etjs2/CNk
6fqkIqeCoS82zQiQeb2BJ1UqMLO/Kg5yiseXULXK1bK3+ox/vHDwfI9BqOnDVgr3
P5VjfVRqwpfNlCJvTEYxKDj3/44EnYvfD+BzbVES8BXIHykeddkItjz393EfweyG
sP0zHaPFjxzA/wusMmwEa/8Uozj4n7DZvQIDAQAB
-----END RSA PUBLIC KEY-----

2024/12/20 07:17:12 Private 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4FJVQw2iQzO5E9/H5zs97OaIlhVfVc18zVQkLq6rC177uLrn
hxjfqh62ktFBDgVRvWTEjkLUBEBmQZf13RUmjG4PWK2kZ5O2hNj63v1afvkM1gFt
tVuHlX+YF3kAZMziM2/oDLlPwLyiWp1N5suGjs6l+83GiASIyYe6JIZHqR0Etjs2
/CNk6fqkIqeCoS82zQiQeb2BJ1UqMLO/Kg5yiseXULXK1bK3+ox/vHDwfI9BqOnD
Vgr3P5VjfVRqwpfNlCJvTEYxKDj3/44EnYvfD+BzbVES8BXIHykeddkItjz393Ef
weyGsP0zHaPFjxzA/wusMmwEa/8Uozj4n7DZvQIDAQABAoIBAQDD76aBtzrwMBGN
Bn55vwlMD+FmFqz7KU3Fm6UvEWpduE1vAfKR0mwrEECw5Q5JzOOk5ou5Jy5BuG6Z
BL7AqWTObKQC9UkRH7jhORWICQwutCM+GmlVa+l178lNV2e8pClAfJLX6lV7KEk3
lQcifMu/mUjqNMcgr7U7Ms6ocJHPZ+IFvmAYg6JGCpVhYeaOrd10tpxc6F3aQ7HY
wsU5H0ZEB4o1DfEZbI+6idUZA4jrLrKMDLAIHVvBbz86W8mkzsJUBp3TH38VtvZC
UBjE0nWU6UAElzJ4t5XiCzoivLqdn2QbBOvEoL2HC/0OmvSxzJnaLxo7r4g2OkOB
8WKcAE2RAoGBAOHzPYeE/6MF+6pGr/hFra7hfHN3MApikZQh3XpbopHMuMZBS6LS
SO3QwgfMsEGG8QAv8eHiyKmu4mzpO0fJQX9+Fr3rO6Z0Lfbi7unclZmX+yaaWGvA
Mhqi4sORgHGzqsLn9LDmN1VXQNNr4s8HzrkAGd8Ld8R2YaWGkCtRpLIjAoGBAP4n
pZhSpg+7sJLyontPjf+eCW8nxmPieDjbkPXiKvtT3VhrKc1k02Egf/cXjSgIkEuM
nPQxkRoIybbVznPqgYJcfFhpnyXzZPJwCsvhRZPXB/aqZ3CTCQRTd3CZgZ6jSfLT
vAN8SgOcarH4FzSv59Ge6mlgXiY10rKfIgddPVKfAoGAeeOX+7V5ml4t5yt+3jXo
fgDR/A/98HxAAGNMcSdhyblgrEKpJMq/4NrO8RowswiyleFHYQ3QJglbyFkBS7Z8
COTiK83sPd1KtnaxX6NJaLQeHjMBJA9oeAoKvmmNmsjLg51R2OQ4UWdiZys6DWku
0YoGatZq46bhAkRXHadLa3UCgYBhk0UfQvPgbHWxJRg+cV+Z+Mm0dDfVl1gCtEFm
NUu9LAh57sKgyYnh60FV0yPtb8Q+TSDhG7qSnTccS9+0Xx8TtoBCzWI9hsGF1oA+
oCE/TjoPeIK4FKtMjuL3RugdyKEWajXvvKMJ2d6Yrx/xqWs97l4e0NG0p8tZqoC9
BQ4LDwKBgEpEsVX6t9ScKvtz9ZcvpmjF8/hHF+s+P7EzivpfPjoY06vRVT1sOI+p
EFSXTH8+GSEH55zfwfQDHyCcInT0aswKVB2aY3WpYLCwtOhvcI3dtiLPDe87pQQm
p/SGNMTdHWKAIpKx5hzluVbBA3ivfH/MnHSThjtoy7TIeLdFRO+p
-----END RSA PRIVATE KEY-----

2024/12/20 07:17:12 loaded external 000be78b2bdf27d2e4d4406fd62d0e88f4e5bb1e57c05f954ad2c1b3664aa672be54
2024/12/20 07:17:12 ======= create a policy session for authorized key ========
2024/12/20 07:17:12 ======= create PolicyAuthorize ========
2024/12/20 07:17:12 ======= create PolicyPCR ========
2024/12/20 07:17:12 PolicyPCR CPBytes 000000000001000b03000080
2024/12/20 07:17:12 Full PolicyCommand: 01160001000b000600400000001000100800000100010100e05255430da24333b913dfc7e73b3dece68896155f55cd7ccd54242eaeab0b5efbb8bae78718dfaa1eb692d1410e0551bd64c48e42d40440664197f5dd15268c6e0f58ada46793b684d8fadefd5a7ef90cd6016db55b87957f9817790064cce2336fe80cb94fc0bca25a9d4de6cb868ecea5fbcdc6880488c987ba248647a91d04b63b36fc2364e9faa422a782a12f36cd089079bd8127552a30b3bf2a0e728ac79750b5cad5b2b7fa8c7fbc70f07c8f41a8e9c3560af73f95637d546ac297cd94226f4c46312838f7ff8e049d8bdf0fe0736d5112f015c81f291e75d908b63cf7f7711fc1ec86b0fd331da3c58f1cc0ff0bac326c046bff14a338f89fb0d9bd0007666f6f6f6f6f6f0014000b01000ac61d48da8af010527d0a5cacd8a9aa78dcdb7da1a6ee5990abd86d05622ab5dc1eaceb901b8e86e5440de35b790925927dc6f02ec62cde9831b5bbf472e9256ef25a6f51b82847cc24f9ed4f6952735a449d82da32de6f333f58195419aea890110de269d49abc03045d984634a43657de66a25f6cd6f6a149e6e15aefb898b97ae54ebed9f63983f1b3a8dbd8239acccd54e6e02c38bbb57ac195c7d639767f80d6d27d389dcd057409a0a2711ec434642195c20462a38654573a9d19e4c53b2ab215035907846d86d68a14917d2ecb2b8b143cbd550edfe336e926065c9e762d53f556e216ca8ebe94b7d5e15062bb8a457cb29874500b48f020a37bd341
2024/12/20 07:17:12 ======= createPrimary ========
2024/12/20 07:17:12 IV: 79cc541e48cfb44d24f3b66f081c359d
2024/12/20 07:17:12 Encrypted e28455a3be
```


---

### Wireshark baseline 

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
    sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
    sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/   # or wherever tpm2.so sits, eg /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so

tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

## create H2 Template
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
     -c primary.ctx \
     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

tpm2_create -g sha256 -G aes128cfb -u key.pub -r key.prv -C primary.ctx -L policy.dat  -p foo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_load -C primary.ctx -u key.pub -r key.prv -n key.name -c key.ctx    
```

As wire format using `sudo tcpdump -s0 -ilo -w trace.cap port 2321`, the command is:

![images/command.png](images/command.png)

The auth session is:
![images/authsession.png](images/authsession.png)

and finally the paramters on the wire

```
 SWTPM_IO_Read: length 58
 80 01 00 00 00 3A 00 00 01 7F 03 00 00 01 [[>>  00 20 
 E2 F6 1C 3F 71 D1 DE FD 3F A9 99 DF A3 69 53 75 
 5C 69 06 89 79 99 62 B4 8B EB D8 36 97 4E 8C F9 
 00 00 00 01 00 0B 03 00 00 80 << ]]
```

![images/parameters.png](images/parameters.png)


to use wireshark, run  `wireshark trace.cap`


