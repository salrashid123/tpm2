
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
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5


## new window 

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/ 

tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23

$ tpm2_pcrread
  sha1:
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    1 : 0x0000000000000000000000000000000000000000000000000000000000000000
    2 : 0x0000000000000000000000000000000000000000000000000000000000000000
    3 : 0x0000000000000000000000000000000000000000000000000000000000000000
    4 : 0x0000000000000000000000000000000000000000000000000000000000000000
    5 : 0x0000000000000000000000000000000000000000000000000000000000000000
    6 : 0x0000000000000000000000000000000000000000000000000000000000000000
    7 : 0x0000000000000000000000000000000000000000000000000000000000000000
    8 : 0x0000000000000000000000000000000000000000000000000000000000000000
    9 : 0x0000000000000000000000000000000000000000000000000000000000000000
    10: 0x0000000000000000000000000000000000000000000000000000000000000000
    11: 0x0000000000000000000000000000000000000000000000000000000000000000
    12: 0x0000000000000000000000000000000000000000000000000000000000000000
    13: 0x0000000000000000000000000000000000000000000000000000000000000000
    14: 0x0000000000000000000000000000000000000000000000000000000000000000
    15: 0x0000000000000000000000000000000000000000000000000000000000000000
    16: 0x0000000000000000000000000000000000000000000000000000000000000000
    17: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    18: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    19: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    20: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    21: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    22: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B


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

Alternatively, if you want to modify the core go-tpm library set to allow easy unmarshalling by reflection, see

* `policy_pcr_tpm2/` : PolicyPCR
* `policy_signed_tpm2`: PolicySigned

edit `$GOPATH/pkg/mod/github.com/google/go-tpm/tpm2/reflect.go`

```golang
func ReqParameters(parms []byte, rspStruct any) error {
	numHandles := len(taggedMembers(reflect.ValueOf(rspStruct).Elem(), "handle", false))
	if len(parms) < 2 {
		return nil
	}

	buf := bytes.NewBuffer(parms)
	for i := numHandles; i < reflect.TypeOf(rspStruct).Elem().NumField(); i++ {
		parmsField := reflect.ValueOf(rspStruct).Elem().Field(i)
		if parmsField.Kind() == reflect.Ptr && hasTag(reflect.TypeOf(rspStruct).Elem().Field(i), "optional") {
			if binary.BigEndian.Uint16(buf.Bytes()) == 0 {
				// Advance the buffer past the zero size and skip to the
				// next field of the struct.
				buf.Next(2)
				continue
			}
		}
		if err := unmarshal(buf, parmsField); err != nil {
			return err
		}
	}
	return nil
}

func CPBytes[R any](cmd Command[R, *R]) ([]byte, error) {
	parms := taggedMembers(reflect.ValueOf(cmd), "handle", true)
	if len(parms) == 0 {
		return nil, nil
	}

	var firstParm bytes.Buffer
	if err := marshalParameter(&firstParm, cmd, 0); err != nil {
		return nil, err
	}
	firstParmBytes := firstParm.Bytes()

	var result bytes.Buffer
	result.Write(firstParmBytes)
	// Write the rest of the parameters normally.
	for i := 1; i < len(parms); i++ {
		if err := marshalParameter(&result, cmd, i); err != nil {
			return nil, err
		}
	}
	return result.Bytes(), nil
}
```

```bash
$ go run policy_signed_tpm2/main.go 

2024/12/13 12:17:44 Public -----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA7H8qotS95oQoYZ6cFDhTYjSEQ9JMtVSHoAPXXfGk6qDvBUHzm0Oz
hrMmVgAyenewUiwyNZsQP4ZdLntDJb9TcUBfTSEaVctdfdNUw57pfw+7p1it13CO
ZlqiZNyM31+Vr0wTPVB39nsRrwGfn1hqyQ8eIgYms81qw3CyyRCnMLAmN+4l9+RP
FB9EGczKWQhOnCf9vuFBiChjHCmoqppIKB57h2nDCLYVxnDgECQ0Q7W1FtZoFb8B
o02rxsGeAEyJ5E/rWd3zNIiEIvZyGRi2RgRTiJce+KN557Iksg6B6huehWy1yGbY
b1i4WNbBXHkXMPQgBMet4iQak92sq0EXrQIDAQAB
-----END RSA PUBLIC KEY-----

2024/12/13 12:17:44 Private -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7H8qotS95oQoYZ6cFDhTYjSEQ9JMtVSHoAPXXfGk6qDvBUHz
m0OzhrMmVgAyenewUiwyNZsQP4ZdLntDJb9TcUBfTSEaVctdfdNUw57pfw+7p1it
13COZlqiZNyM31+Vr0wTPVB39nsRrwGfn1hqyQ8eIgYms81qw3CyyRCnMLAmN+4l
9+RPFB9EGczKWQhOnCf9vuFBiChjHCmoqppIKB57h2nDCLYVxnDgECQ0Q7W1FtZo
Fb8Bo02rxsGeAEyJ5E/rWd3zNIiEIvZyGRi2RgRTiJce+KN557Iksg6B6huehWy1
yGbYb1i4WNbBXHkXMPQgBMet4iQak92sq0EXrQIDAQABAoIBAQDfnwsgtsrtuk84
pzJsSCpINOJQAv13hHtNyfQOJ5zKIux/6zG+wZBysNlx/nO8q4n02UeMupftiU54
0iLXAYeUEctLch6lu0sm2/pNkui0tZq6DTcr/IkZrV/awVUPLiGqhOO4WWtljE9X
TNCzanZmsT3L7EcSQw1NyjWzu2RruoK7UrM9tdEVUlM1Jn9L6p23TQTRyiT/1rFx
3RZsDlP+Nta9KuCXxl+sjcNzPCgxOt+ki8atwxDlEPySeRUZw1L0aXNRY1XQjGR2
gfOnfBFYZPzajK1hLEY07hkJTz3iP4sg6kKWESi1GEhzlixrAo1sMQNQTaXaYBK5
4ysEwEIBAoGBAPLcNXiIaUVdBXf+MD9pR1j2oQPFY7IGKcDxglGHU/ULfn018DnO
Gm2o8KkYVHRK3Yh9wv18DZSSfxMWfR1WDqqCQJN6nM7fUxe2+WAdzJp2ugpVYhu5
konR6WzqUQD7zF5WabyOwvFjoEjQRDNCupp0iRZuU8AyJheWb3xb/amBAoGBAPlK
0b0PzM49P4uKfLxNK64CcvoxvmhEPXqK/zdGJ5OiGOkt7aEQC6QBTeXe1RgBD5fp
8+dJfSX+Yw6kUmbAUyUQOKFsPfOub3ckdxPRc08vsB7f7RQCzqk7Vq7mnFz4x7dS
lkc0378dESUFe14BbKgcBbZA/0Lw2tsJzKNtWEwtAoGAUSaqK2ORoZ7qs+TZJGc+
cwi+Vu8/V/5dN168CBgrQsebdaVvZzFqfVglSquZlN5rVi+H14H7W7j0A2HRXtsh
vXIWt/ERssLHFjaK78YlVzvzAH71cIQ65hihYkaN2MFK0f8YB+zAUT7UEWCeWW6j
wfbM1BT7oU5gkiMvj6OBiIECgYBLCsq4Ltln++f1CWsjA9fyOaqCxhabLG+VQ+Iv
sV6YgmMdTkYKBdp7NClO2RUsdKVNBY/2P5j8pucKsUxcwehFb+ycKwk7IXdMVh3C
SXp8i85ofN/Q9kdfig09+Q14ryrvdFzocnIoBYfzrQLF+YfL0yOlCUvNytMWvIxt
Zaz+wQKBgCOC1Jbk7i92zAC4017hbNV6U26qS3X+5x0sPUGen/5bMWoAfwMl0w7n
IzbDRqvFHy7czu17l87vkZIMx8NBycBF7o3MpUQL4qhSI/TOZklAnqAh5k1MuKhL
9wf3KDr3UQfqc6QD2rarBduW37dHJ0zolHdBBUvwgVtAuA11OsXY
-----END RSA PRIVATE KEY-----

2024/12/13 12:17:44 loaded external 000b9201beca4af3d04b013d4a91f84d93100c1c1f4541e7789b611a9947d4d54ba3
2024/12/13 12:17:44 ======= createPrimary ========
2024/12/13 12:17:44 ======= create ========
2024/12/13 12:17:44 PolicyPCR CPBytes 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
2024/12/13 12:17:44 pcrSelectionSegment 00000001000b03000080
2024/12/13 12:17:44 pcrDigestSegment 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9
2024/12/13 12:17:44 commandParameter 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
2024/12/13 12:17:44 PolicySecret objectHandleHint hex 4000000b
2024/12/13 12:17:44 PolicySecret Name 00044000000b
2024/12/13 12:17:44 PolicySecret PolicyRef 666f6f626172
2024/12/13 12:17:44 PolicySecret CPBytes 4000000b00044000000b666f6f626172
2024/12/13 12:17:44 Recreated PolicySecret objectHandleHint 1073741835
2024/12/13 12:17:44 Recreated PolicySecret nameLengthBytes 0004
2024/12/13 12:17:44 Recreated PolicySecret nameBytes 4000000b
2024/12/13 12:17:44 Recreated PolicySecret nonceBytes 666f6f626172
2024/12/13 12:17:44 Sig 9ab6ff653c2e139e07e12929bbbf63bd849a883149612c10c990a2c4ebd5728bac90b2a8dcbe83b2a30869434c2c9e87ac21a2d37344e363849cb988eafffd061fefedf91b9129bc286d1a13826019af0a90059fbb4d7fcc0f4e1d35431c90827c3d407ff6e20d46fa65e6377ea96da1e7c54dce85c035f2ab4f2274bddbd1b53a1b3ce31b2a144fa2e9dfd3f3324db0df534b9ad2730823898e83bda7550b92c74399e88a8a7d1d0ddebb1c9b5b736976b78eb2c2d88208abb7b3e194215212f6835b9fd56b52b0564b20c8c7c87578cda842379f0649a797f62e9ae10354fd1f12a605efb4817d4b99289e22112299df9a8ad3c167f66c41033393ad2d6711
2024/12/13 12:17:44 IV: 992ab674d70519fcb9e8f8cbfb96912a
2024/12/13 12:17:44 Encrypted 85fddcf1db

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


