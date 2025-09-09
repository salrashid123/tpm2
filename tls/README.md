### mTLS client-server using using tpm2-tss

Snippet which shows how to setup a simple https mtls server using `openssl` and curl with `tpm2tss`


* [TLS and s_server](https://github.com/tpm2-software/tpm2-tss-engine#tls-and-s_server)
* [nginx with TPM based SSL](https://blog.salrashid.dev/articles/2021/nginx_with_tpm_ssl/)
* [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)
* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)

- [c: TLS with TPM based private key](https://gist.github.com/salrashid123/db54e06f47ba7c6d801fe09f9f9c834a)

- python [Python mTLS client/server with TPM based key](https://gist.github.com/salrashid123/4cb714d800c9e8777dfbcd93ff076100)

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

---


## Python

```bash
apt-get update

apt -y install   autoconf-archive   libcmocka0   libcmocka-dev   procps   iproute2   build-essential   git   pkg-config   gcc   libtool   automake   libssl-dev   uthash-dev   autoconf   doxygen  libcurl4-openssl-dev dbus-x11 libglib2.0-dev libjson-c-dev acl swtpm swtpm-tools python3-pip python3-requests python3-flask

cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig


cd
git clone https://github.com/tpm2-software/tpm2-tools.git
  cd tpm2-tools
  ./bootstrap
  ./configure
  make install

cd
git clone https://github.com/tpm2-software/tpm2-openssl.git
cd tpm2-openssl
  ./bootstrap
  ./configure
  make install



mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/ 
export TSS2_LOG=esys+debug

$ openssl version
   OpenSSL 3.0.9 30 May 2023 (Library: OpenSSL 3.0.9 30 May 2023)


git clone https://github.com/salrashid123/ca_scratchpad.git
cd ca_scratchpad

mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr

echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

export SAN=single-root-ca

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out ca/root-ca/private/root-ca.key
   
openssl req -new  -config single-root-ca.conf  -key ca/root-ca/private/root-ca.key \
   -out ca/root-ca.csr  

openssl ca -selfsign     -config single-root-ca.conf  \
   -in ca/root-ca.csr     -out ca/root-ca.crt  \
   -extensions root_ca_ext


### create a server cert
export NAME=server
export SAN="DNS:localhost"

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out certs/$NAME.key

openssl req -new     -config server.conf \
  -out certs/$NAME.csr  \
  -key certs/$NAME.key  -reqexts server_reqext   \
  -subj "/C=US/O=Google/OU=Enterprise/CN=server.domain.com" 

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt  \
    -extensions server_ext

### create a client cert
export NAME=tpmc
export SAN="DNS:client.domain.com"

openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out certs/$NAME.key

openssl req -new  -provider tpm2 -provider default \
      -config client.conf   -out certs/$NAME.csr \
          -key certs/$NAME.key   -subj "/C=US/O=Google/OU=Enterprise/CN=client.domain.com"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -policy extern_pol \
    -extensions client_ext

$ cat tpmc.key 
-----BEGIN TSS2 PRIVATE KEY-----
MIICEgYGZ4EFCgEDoAMBAQECBEAAAAEEggEYARYAAQALAAYAcgAAABAAEAgAAAEA
AQEAyDaWiSc/cRZjXVuL8R3YzzysqhvcXSsabO2NQKR73EJ4NxKG1Q9QmOfnay+E
p1Op2EIEdy3L2Ev43IC9cVwojPkp4UNTj0RPBEGfUoy4pCcxSqdRCTWD5jB5DUG8
KMz6lkhdY39+DsXgieUkkVuWgouMAUEYND9ypHc9kb7N9R1L/TfYkUjohWPnew8w
6WF0gQaZOiZUG+753biUx0xrXQi92fsMNlpcBo6+vWTZjtKzohRbFgBC6RL/yzcC
CtcjZYfUp2XHLR7pGrP+lTwF6T30vpF2VJ4rUSd90f7M9oI+8YhCD3lB2RrRyTe4
7UhVcYFS21OkhmQ3ibZEnOdi/wSB4ADeACAapjcmn7+dwAxM7z57LMl3/pAytfhe
K7cLu0hhWlx1wwAQARrbrL3kKtkIy19XH1wYOS7ypZ66hqU0JkmonptTq0xelguy
v3ak/SMfls2Vrrq6+20W0boQPdVAHl6KoUky4xwDA+fzSvW9tQurhZXkbe6M7yAF
nUBdl+uwZR/e9E+6kbihjiaEvCWqs4YW5ygrigoHVqOA7aTKQ6/4JOgg1pcnt4pX
YLju7KF9ggKtGUDiYqYtiTJ+Y3Xexhv1tv5Iyvw2dbb3An1T5pidlHghqIIQzR7T
Yh9cYFRf
-----END TSS2 PRIVATE KEY-----


openssl rsa -provider tpm2  -provider default -in certs/tpmc.key --text


python3 server.py


export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/ 
export TSS2_LOG=esys+debug

export OPENSSL_CONF=`pwd`/openssl.cnf
python3 client.py
```