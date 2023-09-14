### mTLS client-server using using tpm2-tss

Snippet which shows how to setup a simple https mtls server using `openssl` and curl with `tpm2tss`


* [TLS and s_server](https://github.com/tpm2-software/tpm2-tss-engine#tls-and-s_server)
* [nginx with TPM based SSL](https://blog.salrashid.dev/articles/2021/nginx_with_tpm_ssl/)


For this we will be using a test ca authority

first find a vm where you've [installed tpm2tss](https://github.com/salrashid123/tpm2#installing-tpm2_tools-golang)


Verify

```bash
$ openssl engine -t -c tpm2tss
(tpm2tss) TPM2-TSS engine for OpenSSL
 [RSA, RAND]
     [ available ]

$ openssl rand --engine tpm2tss  -base64 12
engine "tpm2tss" set.
ZSgRvOrcJAQrqdfQ
```

then,

```bash
### first generate client/server keys on the TPM
tpm2tss-genkey -a rsa server.tss
tpm2tss-genkey -a rsa client.tss
## note, we will not be using self-signed stuff since we want to show mtls end to end cleanly
### openssl req -new -x509 -engine tpm2tss -key server.tss  -keyform engine  -out rsa.crt


## get a testing ca i setup here
git clone https://github.com/salrashid123/ca_scratchpad.git
cd ca_scratchpad

## do some background work to setup a new CA
mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out ca/root-ca/private/root-ca.key

openssl req -new  -config single-root-ca.conf  -key ca/root-ca/private/root-ca.key \
   -out ca/root-ca.csr  

openssl ca -selfsign     -config single-root-ca.conf  \
   -in ca/root-ca.csr     -out ca/root-ca.crt  \
   -extensions root_ca_ext


### now that the ca is setup, generate a CSR and sign it with the CA.
#### note that w'ere referencing the TPM engine here:
export NAME=server
export SAN=DNS:server.domain.com

openssl req -new  -engine tpm2tss -keyform engine    -config server.conf \
  -out certs/$NAME.csr   \
  -key ../server.tss \
  -subj "/C=US/O=Google/OU=Enterprise/CN=server.domain.com"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions server_ext


## now do the same for the client certificate
export NAME=user10
export SAN=DNS:user10.domain.com

openssl req -new -engine tpm2tss -keyform engine  \
    -config client.conf \
    -out certs/$NAME.csr \
    -key ../client.tss \
    -subj "/L=US/O=Google/OU=Enterprise/CN=user10.domain.com"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -policy extern_pol \
    -extensions client_ext
```

We're finally ready to run the client/server

```bash
cd ..
echo -n foo > index.html

## start the simple https server using openssl
openssl s_server -cert ca_scratchpad/certs/server.crt \
  -key server.tss -keyform engine -engine tpm2tss \
   -accept 8443 -CAfile ca_scratchpad/ca/root-ca.crt  -Verify 5  -WWW -tlsextdebug

### in a new window, run the client
curl -vvvvv --engine tpm2tss --key-type ENG \
  -H "host: server.domain.com" \
  --resolve  server.domain.com:8443:127.0.0.1 \
  --cert  ca_scratchpad/certs/user10.crt \
  --key client.tss \
  --cacert ca_scratchpad/ca/root-ca.crt \
  https://server.domain.com:8443/index.html

```


The output of the client and server is shown below..done with the tls keys on hardware


### client

```
* Added server.domain.com:8443:127.0.0.1 to DNS cache
* Hostname server.domain.com was found in DNS cache
*   Trying 127.0.0.1:8443...
* Connected to server.domain.com (127.0.0.1) port 8443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ca_scratchpad/ca/root-ca.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Request CERT (13):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Certificate (11):
* TLSv1.3 (OUT), TLS handshake, CERT verify (15):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: C=US; O=Google; OU=Enterprise; CN=server.domain.com
*  start date: Sep 14 12:46:35 2023 GMT
*  expire date: Sep 13 12:46:35 2033 GMT
*  common name: server.domain.com (matched)
*  issuer: C=US; O=Google; OU=Enterprise; CN=Enterprise Root CA
*  SSL certificate verify ok.
> GET /index.html HTTP/1.1
> Host: server.domain.com
> User-Agent: curl/7.74.0
> Accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 ok
< Content-type: text/html
< 
* Closing connection 0
* TLSv1.3 (OUT), TLS alert, close notify (256):
foo
```

#### server
```
engine "tpm2tss" set.
verify depth is 5, must return a certificate
Using default temp DH parameters
ACCEPT
TLS client extension "server name" (id=0), len=22
0000 - 00 14 00 00 11 73 65 72-76 65 72 2e 64 6f 6d 61   .....server.doma
0010 - 69 6e 2e 63 6f 6d                                 in.com
TLS client extension "EC point formats" (id=11), len=4
0000 - 03 00 01 02                                       ....
TLS client extension "supported_groups" (id=10), len=12
0000 - 00 0a 00 1d 00 17 00 1e-00 19 00 18               ............
TLS client extension "next protocol" (id=13172), len=0
TLS client extension "application layer protocol negotiation" (id=16), len=14
0000 - 00 0c 02 68 32 08 68 74-74 70 2f 31 2e 31         ...h2.http/1.1
TLS client extension "encrypt-then-mac" (id=22), len=0
TLS client extension "extended master secret" (id=23), len=0
TLS client extension "post handshake auth" (id=49), len=0
TLS client extension "signature algorithms" (id=13), len=42
0000 - 00 28 04 03 05 03 06 03-08 07 08 08 08 09 08 0a   .(..............
0010 - 08 0b 08 04 08 05 08 06-04 01 05 01 06 01 03 03   ................
0020 - 03 01 03 02 04 02 05 02-06 02                     ..........
TLS client extension "supported versions" (id=43), len=5
0000 - 04 03 04 03 03                                    .....
TLS client extension "psk kex modes" (id=45), len=2
0000 - 01 01                                             ..
TLS client extension "key share" (id=51), len=38
0000 - 00 24 00 1d 00 20 48 1e-e5 c7 94 f9 d2 e0 11 34   .$... H........4
0010 - 2a 22 77 56 f4 f5 62 54-e1 b5 11 2c d2 a9 7d ac   *"wV..bT...,..}.
0020 - a0 dc f2 11 30 0c                                 ....0.
TLS client extension "TLS padding" (id=21), len=182
0000 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0010 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0020 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0030 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0040 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0050 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0060 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0070 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0080 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
0090 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
00a0 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................
00b0 - 00 00 00 00 00 00                                 ......
depth=1 C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
verify return:1
depth=0 L = US, O = Google, OU = Enterprise, CN = user10.domain.com
verify return:1
FILE:index.html
  ```

* [https://github.com/tpm2-software/tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine)

* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
