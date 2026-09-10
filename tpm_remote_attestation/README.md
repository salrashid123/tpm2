## TPM Remote Attestation, Quote/Verify, NewKey Certification with TPM2_Direct


Simple flow which demosntrates several protocols using go-tpm Direct API

Also see 

- [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)


#### Start Simulator

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --ecc  --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5


tpm2_getekcertificate -X -o ECcert.bin

openssl x509 -in ECcert.bin -inform DER -noout -text
```

#### QuickStart

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"
go run get_ek/main.go  -ekCertFile=output/ek.cert -ekPubFile=output/ekpub.pem -tpm-path=127.0.0.1:2321

go run get_ak/main.go -akKeyFile=output/ak.pem -akPubFile=output/akpub.pem -tpm-path=127.0.0.1:2321

go run make_credential/main.go -akPubFile output/akpub.pem \
   -credentialBlobFile output/credentialblob.bin -ekPubFile output/ekpub.pem \
    -encryptedSecret output/encryptedSecret.bin -secret somerandomsecret

go run activate_credential/main.go  -akKeyFile output/ak.pem \
   -credentialBlobFile output/credentialblob.bin \
   -encryptedSecret output/encryptedSecret.bin -tpm-path 127.0.0.1:2321

go run quote/main.go -akKeyFile output/ak.pem -pcr 23 \
   -quotedFile output/quoted.bin -quotedSignatureFile output/quotedsignature.bin \
   -secret "meet me at..." -tpm-path "127.0.0.1:2321"

go run quote_verify/main.go -akPubFile output/akpub.pem \
   -ekPubFile output/ekpub.pem -pcr 23 -quotedFile output/quoted.bin \
   -quotedSignatureFile output/quotedsignature.bin -secret "meet me at..."

go run make_key/main.go  -akKeyFile output/ak.pem \
   -akPubFile output/akpub.pem -newKeyFile output/nk.pem \
   -tpm-path "127.0.0.1:2321"

go run verify_key/main.go -akPubFile output/akpub.pem -ekPubFile "output/ekpub.pem" \
   -certificationSignature output/certifysignature.bin \
   -certifyInfoFile output/certify.bin -secret "meet me at..." 
```

### Get EndorsementKey

Extracts and writes the EK x509, endorsementPublic key PEM 

```bash
go run get_ek/main.go  -ekCertFile=output/ek.cert -ekPubFile=output/ekpub.pem -tpm-path=127.0.0.1:2321


2026/09/10 10:13:47 ======= Init  ========
2026/09/10 10:13:47 ======= Read NV for EKCert ========
2026/09/10 10:13:47 Name: 000bc406c8d25564a5fbb3b61089133cb52df7c840b4c56d74eb703060c545ce73f6
2026/09/10 10:13:47 Size: 1017
2026/09/10 10:13:47 TPM Max NV buffer 1024
-----BEGIN CERTIFICATE-----
MIID9TCCAl2gAwIBAgICCWUwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0
cG0tbG9jYWxjYTAgFw0yNjA5MTAxNDExMjJaGA85OTk5MTIzMTIzNTk1OVowEjEQ
MA4GA1UEAxMHdW5rbm93bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJt35fxcewH3/2pHiGoflmU3oQSTXqOBU74zwAy9vVoFTz5uKnkxKeQ9O15pKl+T
OakwxxAFuGtnG3BxVczk0U7ersblQWAVPH9mG/QOwLi8VZ2F9EsFDsYuudXxJMS+
97Zwfhhl7izPKzgjCB3dozO5naem+g6XAtallj+Js6I32Li5IJsvuJXHlpiGzr7B
A+ng4xC77pc6r5t8P+qEh6u25a9CnZFsRF41XelkrTQF61UDUFonSN0ctvbyiVCA
+09mJKrDgl5tfOUaj2ZT2tDeyZGYDaFlwt+qjEgTdh2m0ZC0zX7L74iE6VzhB/co
3Tfr5GH1Nl64u8ic2ET81L0CAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBS
BgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeB
BQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDI0MDEyNTAMBgNVHRMBAf8EAjAA
MCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgC3MB8GA1UdIwQYMBaA
FC9tUdt3Nuy5Lc3iJ4AxyLHsw4e0MA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0B
AQsFAAOCAYEAJWui49g2rrL5iLK6ZeJ5XL+d20Bm1e5PtEjFSEovgIEb9NN0C+Ei
Qwp/fCZqlw/MeHj9yRzfvkx78fvSIKodUL5rG0LnCVMdlLfyAI26ax80JckBB3ZP
eKLmR3nPMzPny7Ai72WJOfqh3WTlp6WWQwrhqaML4ZWKmja7d8pPOOMkkTCcm3vP
m4sG0CJOGkKTMlhX7Di+1v3ZD261gbvNOGllPz7t2L1auqrJHS2g3RvJuBqP+Ziu
/91VCD+cRgFT865k6U4NGfJ2b4oo6FYDXVKN1CZM9+k9Ir7ef1E2ezc77TjZIKRJ
ZY2JJvCzk0ZN7ivJ+eh6vzbO7VScfURw2lgH+ZaHu+Y4qpPZgEbH9MzKZRj8+Bj/
sy7fihk1sdWTvKYdaoLcAueDsAtM8c8kYcxRa9O51iZcHVwNd7Z++e8LYoTJCI4b
o946nvvdgb4/t4ou+TWysfqvrlwz0D1UpSuF58ue0P/oUTP+duLB+42BRk3M1//i
eEDtsEykcJnH
-----END CERTIFICATE-----

2026/09/10 10:13:47 EK Certificate: 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2405 (0x0965)
        Signature Algorithm: SHA256-RSA
        Issuer: CN=swtpm-localca
        Validity
            Not Before: Sep 10 14:11:22 2026 UTC
            Not After : Dec 31 23:59:59 9999 UTC
        Subject: CN=unknown
        Subject Public Key Info:
            Public Key Algorithm: RSA
                Public-Key: (2048 bit)
                Modulus:
                    9b:77:e5:fc:5c:7b:01:f7:ff:6a:47:88:6a:1f:96:
                    65:37:a1:04:93:5e:a3:81:53:be:33:c0:0c:bd:bd:
                    5a:05:4f:3e:6e:2a:79:31:29:e4:3d:3b:5e:69:2a:
                    5f:93:39:a9:30:c7:10:05:b8:6b:67:1b:70:71:55:
                    cc:e4:d1:4e:de:ae:c6:e5:41:60:15:3c:7f:66:1b:
                    f4:0e:c0:b8:bc:55:9d:85:f4:4b:05:0e:c6:2e:b9:
                    d5:f1:24:c4:be:f7:b6:70:7e:18:65:ee:2c:cf:2b:
                    38:23:08:1d:dd:a3:33:b9:9d:a7:a6:fa:0e:97:02:
                    d6:a5:96:3f:89:b3:a2:37:d8:b8:b9:20:9b:2f:b8:
                    95:c7:96:98:86:ce:be:c1:03:e9:e0:e3:10:bb:ee:
                    97:3a:af:9b:7c:3f:ea:84:87:ab:b6:e5:af:42:9d:
                    91:6c:44:5e:35:5d:e9:64:ad:34:05:eb:55:03:50:
                    5a:27:48:dd:1c:b6:f6:f2:89:50:80:fb:4f:66:24:
                    aa:c3:82:5e:6d:7c:e5:1a:8f:66:53:da:d0:de:c9:
                    91:98:0d:a1:65:c2:df:aa:8c:48:13:76:1d:a6:d1:
                    90:b4:cd:7e:cb:ef:88:84:e9:5c:e1:07:f7:28:dd:
                    37:eb:e4:61:f5:36:5e:b8:bb:c8:9c:d8:44:fc:d4:
                    bd
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Extended Key Usage:
                EK Certificate
            X509v3 Subject Alternative Name: critical
                TPM Manufacturer: id:00001014
                TPM Model: swtpm
                TPM Version: id:20240125
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Directory Attributes:
                TPM Specification: Family: 2.0, Level: 0, Revision: 183
            X509v3 Authority Key Identifier:
                2F:6D:51:DB:77:36:EC:B9:2D:CD:E2:27:80:31:C8:B1:EC:C3:87:B4
            X509v3 Key Usage: critical
                Key Encipherment
    Signature Algorithm: SHA256-RSA
         25:6b:a2:e3:d8:36:ae:b2:f9:88:b2:ba:65:e2:79:5c:bf:9d:
         db:40:66:d5:ee:4f:b4:48:c5:48:4a:2f:80:81:1b:f4:d3:74:
         0b:e1:22:43:0a:7f:7c:26:6a:97:0f:cc:78:78:fd:c9:1c:df:
         be:4c:7b:f1:fb:d2:20:aa:1d:50:be:6b:1b:42:e7:09:53:1d:
         94:b7:f2:00:8d:ba:6b:1f:34:25:c9:01:07:76:4f:78:a2:e6:
         47:79:cf:33:33:e7:cb:b0:22:ef:65:89:39:fa:a1:dd:64:e5:
         a7:a5:96:43:0a:e1:a9:a3:0b:e1:95:8a:9a:36:bb:77:ca:4f:
         38:e3:24:91:30:9c:9b:7b:cf:9b:8b:06:d0:22:4e:1a:42:93:
         32:58:57:ec:38:be:d6:fd:d9:0f:6e:b5:81:bb:cd:38:69:65:
         3f:3e:ed:d8:bd:5a:ba:aa:c9:1d:2d:a0:dd:1b:c9:b8:1a:8f:
         f9:98:ae:ff:dd:55:08:3f:9c:46:01:53:f3:ae:64:e9:4e:0d:
         19:f2:76:6f:8a:28:e8:56:03:5d:52:8d:d4:26:4c:f7:e9:3d:
         22:be:de:7f:51:36:7b:37:3b:ed:38:d9:20:a4:49:65:8d:89:
         26:f0:b3:93:46:4d:ee:2b:c9:f9:e8:7a:bf:36:ce:ed:54:9c:
         7d:44:70:da:58:07:f9:96:87:bb:e6:38:aa:93:d9:80:46:c7:
         f4:cc:ca:65:18:fc:f8:18:ff:b3:2e:df:8a:19:35:b1:d5:93:
         bc:a6:1d:6a:82:dc:02:e7:83:b0:0b:4c:f1:cf:24:61:cc:51:
         6b:d3:b9:d6:26:5c:1d:5c:0d:77:b6:7e:f9:ef:0b:62:84:c9:
         08:8e:1b:a3:de:3a:9e:fb:dd:81:be:3f:b7:8a:2e:f9:35:b2:
         b1:fa:af:ae:5c:33:d0:3d:54:a5:2b:85:e7:cb:9e:d0:ff:e8:
         51:33:fe:76:e2:c1:fb:8d:81:46:4d:cc:d7:ff:e2:78:40:ed:
         b0:4c:a4:70:99:c7

2026/09/10 10:13:47 ======= EKPub ========
2026/09/10 10:13:47 Name 000b652dfc13787c8cbde823607c0d99f485bfb4733c0e92410f7fd4051aa2b30c0f
2026/09/10 10:13:47 EK public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm3fl/Fx7Aff/akeIah+W
ZTehBJNeo4FTvjPADL29WgVPPm4qeTEp5D07XmkqX5M5qTDHEAW4a2cbcHFVzOTR
Tt6uxuVBYBU8f2Yb9A7AuLxVnYX0SwUOxi651fEkxL73tnB+GGXuLM8rOCMIHd2j
M7mdp6b6DpcC1qWWP4mzojfYuLkgmy+4lceWmIbOvsED6eDjELvulzqvm3w/6oSH
q7blr0KdkWxEXjVd6WStNAXrVQNQWidI3Ry29vKJUID7T2YkqsOCXm185RqPZlPa
0N7JkZgNoWXC36qMSBN2HabRkLTNfsvviITpXOEH9yjdN+vkYfU2Xri7yJzYRPzU
vQIDAQAB
-----END PUBLIC KEY-----

```

### Create new AttestationKey

Creates a new AK and write the public PEM file as well as the tpm keyfile

```bash
go run get_ak/main.go -akKeyFile=output/ak.pem -akPubFile=output/akpub.pem -tpm-path=127.0.0.1:2321

2026/09/10 10:14:37 ======= Init  ========
2026/09/10 10:14:37 ======= EKPub ========
2026/09/10 10:14:37 primaryKey Name 000b652dfc13787c8cbde823607c0d99f485bfb4733c0e92410f7fd4051aa2b30c0f
2026/09/10 10:14:37 AK Name 000b0cc20fb86864165581cf9b7e94231b5d5ced7ba69899ad8b4079f6962addc66a
2026/09/10 10:14:37 RSA AK Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz4Tvc5obDde8kJdz8S0g
PitUHFETvvp9mw4jRAgRk3SSRGyJQZeQe8fKhf595Vz+nNsxnL5rQ/DnKURzaPeG
hu9jhG8HbBAWZI1pXFVs8gKVJI9rl/KVB/iCzs41MK1rhqPQ5d8ca5Kf3KxIYEW0
dzv2IDUUh0LlIRZifSyGveI/dhZSt4jEq0CjckaNzmP7kMSaKCj5FMgBDc/d40Xp
rbuTmL6Jv+YVAuHSsmWg4es4q0LsSsEyDVTKe6TNMMLNl4+VxvhFixkOOIUY2ukt
ZBU00kISP9VbpcLy8Apk59ZEMY2I48U1NYr91kND4wFSUIJlZek2ze/w/dEnxe/R
WwIDAQAB
-----END PUBLIC KEY-----
```

### MakeCredential

Read the EKPEM and AKPEM and execute MakeCredential

Write the encryptedSecret and CredentialBlob to file

```bash
go run make_credential/main.go -akPubFile output/akpub.pem \
   -credentialBlobFile output/credentialblob.bin -ekPubFile output/ekpub.pem \
    -encryptedSecret output/encryptedSecret.bin -secret somerandomsecret

2026/09/10 10:15:38 key Primary Name: 000b652dfc13787c8cbde823607c0d99f485bfb4733c0e92410f7fd4051aa2b30c0f
2026/09/10 10:15:38 key Name: 000b0cc20fb86864165581cf9b7e94231b5d5ced7ba69899ad8b4079f6962addc66a
2026/09/10 10:15:38 CredentialBLob 0020fbb8676ed8fa47ef5e9fd3ca0e4be5f56385978e317e1cb7d52b5c232c5714a538f8350d91cbdc0781dda08c4ef32f0f4097
```

### ActivateCredential

Read the EK,AK TPM Pem file, encryptedSecret and credentialblob and extract the secret


```bash
go run activate_credential/main.go  -akKeyFile output/ak.pem \
   -credentialBlobFile output/credentialblob.bin \
   -encryptedSecret output/encryptedSecret.bin -tpm-path 127.0.0.1:2321

somerandomsecret
```

### Quote

Request a Quote over pcr=23 and a secret. Write the signature and quote to file

```bash
go run quote/main.go -akKeyFile output/ak.pem -pcr 23 \
   -quotedFile output/quoted.bin -quotedSignatureFile output/quotedsignature.bin \
   -secret "meet me at..." -tpm-path "127.0.0.1:2321"

2026/09/10 10:18:59 attestation secret:   [meet me at...]
2026/09/10 10:18:59 signature: K+noEKqBTBlKu46y/BNR8lsIIKh0pq+wwNiTGDAf1oMOemfY96pLPT5SojSB6PfPaYmraW+h4uDeIFdYnvy6I05JxgqdSM2gM/QszSmv4LRmzrW5/0BnOU6Tb7FNs0cVOn15jiq07mMEQyAc/utb2Dq8MNMv+9EmkCphJp9rg29pxKJQeZyLwxF8WPGf5G5PeroiO+bd84oSLZPD4QU30uvphqYfayg8RuUWMsXlTM2Ytblk1xwzXF+zwQrU6U5lA2UopNbMRXa1qqB7z2frI1VUntZz5fkJCM/6LVb5cqMEkKl51iWEtRcmeWhVuTJL1+ZWCLzpSWN0gkUnLY6SNg==
2026/09/10 10:18:59 verified
```


### QuoteVerify

Verfiy the quote covers pcr23 and includes the nonce

```bash
2026/09/10 10:19:34 key Primary Name: 000b652dfc13787c8cbde823607c0d99f485bfb4733c0e92410f7fd4051aa2b30c0f
2026/09/10 10:19:34 key Name: 000b0cc20fb86864165581cf9b7e94231b5d5ced7ba69899ad8b4079f6962addc66a
2026/09/10 10:19:34 attestation secret:   [meet me at...]
2026/09/10 10:19:34 signature: K+noEKqBTBlKu46y/BNR8lsIIKh0pq+wwNiTGDAf1oMOemfY96pLPT5SojSB6PfPaYmraW+h4uDeIFdYnvy6I05JxgqdSM2gM/QszSmv4LRmzrW5/0BnOU6Tb7FNs0cVOn15jiq07mMEQyAc/utb2Dq8MNMv+9EmkCphJp9rg29pxKJQeZyLwxF8WPGf5G5PeroiO+bd84oSLZPD4QU30uvphqYfayg8RuUWMsXlTM2Ytblk1xwzXF+zwQrU6U5lA2UopNbMRXa1qqB7z2frI1VUntZz5fkJCM/6LVb5cqMEkKl51iWEtRcmeWhVuTJL1+ZWCLzpSWN0gkUnLY6SNg==
2026/09/10 10:19:34 verified
```

### Make a new key and certify it with AK

Generate a new key and write the TPMPEM key as well as the regular ECC PublicKey to file

```bash
go run make_key/main.go -newKeyPubPEM=output/nkpub.pem -akKeyFile output/ak.pem \
   -akPubFile output/akpub.pem -newKeyFile output/nk.pem \
   -tpm-path "127.0.0.1:2321"

2026/09/10 10:22:20 ======= Init  ========
2026/09/10 10:22:20 ======= EKPub ========
2026/09/10 10:22:20 primaryKey Name 000bfb928ffe9bbc45ee110170c902d11b48305f9a0599ea5aef9d0d3274d1b481ab
2026/09/10 10:22:20 NewKey Name 000b99c8162258fa77e3ba0c8b716d090808c28cbfc4d2704512071c32b9d458aa59
2026/09/10 10:22:20 ECC NewKey Key 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvTDXFD9PW6jLD7DQPDWxzwd4MbGQ
SDXz33D15VwRBCKHIkz7AtRsAHHxnKEAigwksJc0IDm4J0rok5n8WS0hoA==
-----END PUBLIC KEY-----

2026/09/10 10:22:20 Certify Response of Signature 
GqamO8OHV4llNlbS8PF0Ft4FFQjb8DghX772C8X/ei32ihv7VmyH9IZXekxOJpncCvgxnvtUk0LY2Ha60RElY5EB5WvOluK2s4AJ/zqauIXm9aXyeM9d6nRszd1k3gkW41SQFIWvGcKydHgQL5OgXXVSoO7HpDiC1blHFY0Y3pQRui3/jMaJTrsjiRuyz73SfSDm6kjbDQKSiKfwVmN82uf1c8hv4LBL16ScDIu+H2xv0W7hMsZr3T1+uFGha7E+s8oSqo+b5dyLcipJUg79deE4i2MLUkOFlj40fMPy5mqvRd1hb87LTQMMa37/o47LNsaiZhi2TjQmusjTqmOKgQ==
2026/09/10 10:22:20 Certify Response for Key Name 000b99c8162258fa77e3ba0c8b716d090808c28cbfc4d2704512071c32b9d458aa59
2026/09/10 10:22:20 Certify Extra Data foooo
2026/09/10 10:22:20 Attestation Verified
```


### Verify New key Certification by AK

Read the AK, EK the certifiction signature, the new ECC PEM key output/nkpub.pem  and verify

note the new key "name" is the one that is certified by the ak and matches the derived name from nkpub.pem name

```bash
go run verify_key/main.go -akPubFile output/akpub.pem -newKeyPubPEM=output/nkpub.pem -ekPubFile "output/ekpub.pem" \
   -certificationSignature output/certifysignature.bin \
   -certifyInfoFile output/certify.bin -secret "meet me at..." 

2026/09/10 10:23:20 key Primary Name: 000b652dfc13787c8cbde823607c0d99f485bfb4733c0e92410f7fd4051aa2b30c0f
2026/09/10 10:23:20 AK key Name: 000b0cc20fb86864165581cf9b7e94231b5d5ced7ba69899ad8b4079f6962addc66a
2026/09/10 10:23:20 Derived Name 000b99c8162258fa77e3ba0c8b716d090808c28cbfc4d2704512071c32b9d458aa59
2026/09/10 10:23:20 Certify Response of Signature 
GqamO8OHV4llNlbS8PF0Ft4FFQjb8DghX772C8X/ei32ihv7VmyH9IZXekxOJpncCvgxnvtUk0LY2Ha60RElY5EB5WvOluK2s4AJ/zqauIXm9aXyeM9d6nRszd1k3gkW41SQFIWvGcKydHgQL5OgXXVSoO7HpDiC1blHFY0Y3pQRui3/jMaJTrsjiRuyz73SfSDm6kjbDQKSiKfwVmN82uf1c8hv4LBL16ScDIu+H2xv0W7hMsZr3T1+uFGha7E+s8oSqo+b5dyLcipJUg79deE4i2MLUkOFlj40fMPy5mqvRd1hb87LTQMMa37/o47LNsaiZhi2TjQmusjTqmOKgQ==
2026/09/10 10:23:20 Certify CreationObjectName 000b99c8162258fa77e3ba0c8b716d090808c28cbfc4d2704512071c32b9d458aa59
2026/09/10 10:23:20 Certify Extra Data foooo
2026/09/10 10:23:20 Attestation Verified
```