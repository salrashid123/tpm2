
## Extract ekcert from tpm and seal data against it

The following seals data to a public key extracted from a **REAL** TPM (i.,e my raspberry pi).

Then we'll seal some data against the ekcert such that it can only get decrypted on that rasp-pi alone

also see

* [nginx with TPM based SSL](https://blog.salrashid.dev/articles/2021/nginx_with_tpm_ssl/)
* [Sealing RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys#acquire-and-verify-ekcert)

### 1. ON TPM

Read value of any PCR, eg: `23`

```bash
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

# get ekcert from tpm nvram
$ tpm2_getekcertificate -X -o ECcert.bin

$ openssl x509 -in ECcert.bin -inform DER -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 145633230 (0x8ae2fce)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM), CN = Infineon OPTIGA(TM) TPM 2.0 RSA CA 041
        Validity
            Not Before: Oct 18 11:35:43 2018 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:d0:01:93:97:af:9c:52:b6:37:80:65:78:a2:ef:
                    db:b6:c1:d8:22:17:cf:62:d0:47:c6:87:f2:f2:38:
                    08:63:54:7f:30:c0:48:df:a0:8b:6f:1d:e8:c4:6c:
                    10:61:c4:67:38:9f:ff:9f:48:dd:e8:92:87:ba:78:
                    42:f7:11:fe:11:15:e5:97:c9:4a:68:d8:3e:69:8f:
                    95:8d:71:90:b9:18:32:4a:58:78:0c:64:7b:9c:01:
                    de:d1:58:54:e6:20:ff:80:18:04:c4:40:09:88:ff:
                    e0:ce:bb:cf:b5:92:66:1a:67:81:ab:e6:2a:42:d0:
                    c1:80:43:9a:9d:5d:13:d2:17:dc:5f:39:63:46:da:
                    6d:43:6e:25:68:39:a9:c3:1c:c8:32:c1:ed:3c:26:
                    00:0c:cc:e4:6d:68:ca:46:e5:ab:e3:e8:79:3f:0a:
                    50:9a:67:f6:f6:a7:01:e3:28:6b:e6:79:83:f2:10:
                    da:3d:ff:63:ca:c6:cf:de:d8:bb:c6:94:4e:d8:b8:
                    55:f9:4b:a1:c9:dd:ae:04:4c:a7:f9:3d:ed:f7:e8:
                    bc:18:8f:4e:36:cb:b9:49:bd:e2:20:f4:36:d2:c6:
                    21:f6:72:a2:86:c5:2a:df:1f:17:6f:b7:09:13:ca:
                    93:06:9b:cf:9a:ff:4b:e9:36:79:cb:77:2c:88:a7:
                    b2:03
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            Authority Information Access: 
                CA Issuers - URI:http://pki.infineon.com/OptigaRsaMfrCA041/OptigaRsaMfrCA041.crt

            X509v3 Key Usage: critical
                Key Encipherment
            X509v3 Subject Alternative Name: critical
                DirName:/2.23.133.2.1=id:49465800/2.23.133.2.2=SLM 9670/2.23.133.2.3=id:0D0B
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://pki.infineon.com/OptigaRsaMfrCA041/OptigaRsaMfrCA041.crl

            X509v3 Certificate Policies: 
                Policy: 1.2.276.0.68.1.20.1

            X509v3 Authority Key Identifier: 
                keyid:56:F6:B5:97:39:63:01:18:5B:91:D8:00:AC:EE:91:62:19:E3:A6:BB

            X509v3 Extended Key Usage: 
                2.23.133.8.1
            X509v3 Subject Directory Attributes: 
                0.0...g....1.0...2.0.......
    Signature Algorithm: sha256WithRSAEncryption
         38:73:a1:3e:01:30:b9:ec:91:e5:c6:a0:6e:9e:05:46:46:e4:
         72:fb:ba:ac:05:05:0c:df:7b:73:58:a8:f4:e0:1f:62:be:d1:
         89:18:51:1a:fc:d5:c6:35:c0:01:bb:5f:23:cb:cb:7f:e3:77:
         9e:96:01:2d:18:22:e9:12:d1:6f:ec:4d:c1:24:72:2e:cc:3b:
         ff:d0:b1:7e:89:b1:cc:b2:d4:ac:4a:35:bd:13:33:f8:cd:af:
         c6:55:61:6d:db:38:7b:1c:69:8e:a5:ab:31:28:68:10:6d:75:
         48:f5:5f:24:22:dc:a4:fd:57:0c:1c:f3:9a:93:67:0f:0f:74:
         28:67:62:a8:df:9b:40:64:3a:62:09:61:f6:1d:e8:1d:1a:88:
         03:4f:8f:47:95:c6:1d:0d:ac:71:8d:b1:98:c3:23:4a:65:fd:
         59:84:e9:b6:71:f9:6f:41:bc:07:6d:91:c4:6a:f1:86:ca:77:
         6b:bb:9b:d3:ae:aa:81:bd:8e:e6:ef:47:55:39:1d:1e:5c:4a:
         33:33:01:b6:43:85:5b:df:11:7b:51:7b:9a:53:00:b2:62:b2:
         df:4e:c8:6e:b9:c1:30:81:8e:aa:2d:8c:5e:7c:4a:15:71:d9:
         2f:a5:3b:db:84:fd:0f:f1:7e:4d:e0:86:46:0d:b8:b2:00:a6:
         eb:fd:90:03:a7:cb:b7:d8:15:59:d2:46:16:38:56:c3:a8:81:
         a1:57:93:b2:33:7c:a0:10:7d:2a:27:ca:4b:88:48:03:39:a7:
         5d:03:9c:e1:e2:1e:ed:a3:1b:bd:2a:bb:d7:33:be:f5:5e:45:
         1b:92:b7:23:7b:f7:97:44:96:5a:ce:37:71:f1:63:95:d6:92:
         3f:9c:bc:8b:80:26:1f:2e:2f:8d:05:cb:14:a4:a2:eb:bc:65:
         e5:89:bd:f6:2f:41:05:52:96:e2:c8:a9:81:04:9c:e9:f8:87:
         5e:40:15:34:52:d8:57:c7:fc:98:6e:64:39:f0:ad:8c:b2:2d:
         e5:c3:b5:6b:92:7e:e3:bb:56:6e:40:ec:4f:df:13:2c:52:4c:
         b1:87:b2:d0:dc:c9:be:db:6a:bf:c0:d2:bb:13:f0:cc:b9:3b:
         9e:a3:82:17:a8:44:2f:1e:ba:a7:f9:ad:53:89:e8:04:de:b4:
         79:46:63:17:ce:56:22:2c:a9:9b:0e:75:28:25:a5:fb:54:82:
         ec:69:3f:fe:2d:82:f8:16:1a:34:9c:15:2e:ec:57:14:7b:fe:
         21:5b:83:a4:76:17:dc:0f:7c:93:67:29:58:91:a1:e0:f0:e0:
         94:1c:0b:af:a2:37:12:dc:f4:dc:27:9b:4c:a1:ae:cf:66:af:
         25:4a:66:78:87:cb:a9:fe


# extract public key
$ openssl  x509 -pubkey -noout -in ECcert.bin  -inform DER 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AGTl6+cUrY3gGV4ou/b
tsHYIhfPYtBHxofy8jgIY1R/MMBI36CLbx3oxGwQYcRnOJ//n0jd6JKHunhC9xH+
ERXll8lKaNg+aY+VjXGQuRgySlh4DGR7nAHe0VhU5iD/gBgExEAJiP/gzrvPtZJm
GmeBq+YqQtDBgEOanV0T0hfcXzljRtptQ24laDmpwxzIMsHtPCYADMzkbWjKRuWr
4+h5PwpQmmf29qcB4yhr5nmD8hDaPf9jysbP3ti7xpRO2LhV+Uuhyd2uBEyn+T3t
9+i8GI9ONsu5Sb3iIPQ20sYh9nKihsUq3x8Xb7cJE8qTBpvPmv9L6TZ5y3csiKey
AwIDAQAB
-----END PUBLIC KEY-----
```

to read the ekpublc key:

```bash
$ tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q

$ tpm2_readpublic -c primary.ctx -o ek.pem -f PEM -Q
```

Copy the cert or public key to local laptop as `ekpub.pem`

### 2. ON Local

with `ekpub.pem`:

```bash
go run main.go  --mode=seal \
   --secret "hello world" \
   --ekPubFile=ekpub.pem \
   --pcrValues=23=0000000000000000000000000000000000000000000000000000000000000000   \
   --sealedDataFile=sealed.dat --logtostderr=1 -v 10
```

copy `sealed.dat` to remote tpm


### 3. ON TPM

```bash
git clone https://github.com/salrashid123/gcp_tpm_sealed_keys.git
cd gcp_tpm_sealed_keys/

go run symmetric/main.go --mode=unseal --sealedDataFile=sealed.dat --logtostderr=1 -v 10

I0521 10:43:09.738789    7149 main.go:148] Unsealed secret: hello world
```
