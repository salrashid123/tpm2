
### issue CSR from EKRSA (signing)


see https://github.com/stefanberger/swtpm/issues/1061


this allows you to issue a csr from a _restricted_ EKRSA signing key

see pg 12:  https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf


```
One use case for a signing EK is to sign the Certificate Signing Request (CSR) for an Initial Device
Identifier (IDevID) key. The IDevID key is a TPM-generated key that is used as an initial identity for
secure device authentication (see IEEE 802.1AR [10]). The CSR can be signed with the command
TPM2_Sign(). The hash calculated over the certification request information is passed to the TPM in
the digest command parameter; the inScheme command parameter specifies the signing scheme.
The issuer of the IDevID certificate could verify the CSR signature to ensure that the chip requesting
the IDevID certificate is privileged to receive it. Therefore, the issuer could have a list of EK certificates
of all valid TPMs a product manufacturer has purchased. Alternatively, a CSR could be signed by an
Attestation Key.
```


```bash
docker run -ti debian /bin/bash

apt-get update
apt-get install git wget curl socat net-tools gnutls-bin tpm2-tools autoconf automake expect libjson-glib-dev libglib2.0-dev libtool build-essential libssl-dev libtasn1-6-dev gawk pkg-config libjson-c-dev libgnutls28-dev libseccomp-dev libfuse3-dev -y

git clone https://github.com/stefanberger/libtpms.git
cd libtpms
./autogen.sh  --with-gnutls
make
make install
cd ..


git clone https://github.com/stefanberger/swtpm.git
cd swtpm
./autogen.sh  --prefix=/usr --with-cuse
make
make install

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/

wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin


### start swtpm

rm -rf myvtpmA && mkdir myvtpmA && mkdir certsA
swtpm_setup --tpmstate myvtpmA  --tpm2 --create-ek-cert --create-platform-cert  --allow-signing --write-ek-cert-files .
swtpm socket --tpmstate dir=myvtpmA --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear  --log level=2



export PATH=$PATH:/usr/local/go/bin
export TPM2TOOLS_TCTI="swtpm:port=2321"

tpm2_getekcertificate -X -o ECcert.bin
openssl x509 -in ECcert.bin -inform DER -noout -text
openssl x509 -inform der -in ECcert.bin -out ECcert.pem

### note that is not suitable for tls
openssl x509 -noout -in ECcert.pem -purpose
    Certificate purposes:
    SSL client : No
    SSL client CA : No
    SSL server : No
    SSL server CA : No


```

then


```bash
root@d8ca9444b2ef:/app# go run main.go 
2025/10/02 13:46:42 ======= EK ========
2025/10/02 13:46:42 Name 000b7f236d68869c7bc10d9c08d6767c7f090303921b6fb8b1c1b5c1cc3bb5aec7e5
2025/10/02 13:46:42 RSA createPrimary public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnWT7kkYYX32W3ZIlM5tD
xK9zNfhBxDgStLw5zudPZSD34y1VV5ycdVYGd9VcFeTT0ttG+vgKj/rKUghwJoIT
L6N6BVPFWT8U57wOjeRhUVsD3AtjTptgJ5O3h25eNz0Mj6mwMyi9zjQ/2509bBcx
VDfyoJie4HXj/zlN9QSDWB8xkG0VKraYfTuoWsCvAC2yoYBROoPFXkIUdhoWB0xh
nSoBOJUOl2g+KvW8vBksXUN/JmPTUxIsLXV+gvAjsKI0XF5W42kHd2jSiLxeTPcF
ZEBNuVGCoB9vRjYRNU+9B+86jHrN78jh07xFi7NgSXn+O0uOOyzXu0CqKz6m8+EG
GwIDAQAB
-----END PUBLIC KEY-----

2025/10/02 13:46:42 Creating CSR
2025/10/02 13:46:42 wrote csr.pem
root@d8ca9444b2ef:/app# cat csr.pem 
-----BEGIN CERTIFICATE REQUEST-----
MIIC5TCCAc0CAQAwcTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzARBgNV
BAsTCkVudGVycHJpc2UxDjAMBgNVBAMTBWZvb29vMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAnWT7kkYYX32W3ZIlM5tDxK9zNfhBxDgStLw5zudPZSD3
4y1VV5ycdVYGd9VcFeTT0ttG+vgKj/rKUghwJoITL6N6BVPFWT8U57wOjeRhUVsD
3AtjTptgJ5O3h25eNz0Mj6mwMyi9zjQ/2509bBcxVDfyoJie4HXj/zlN9QSDWB8x
kG0VKraYfTuoWsCvAC2yoYBROoPFXkIUdhoWB0xhnSoBOJUOl2g+KvW8vBksXUN/
JmPTUxIsLXV+gvAjsKI0XF5W42kHd2jSiLxeTPcFZEBNuVGCoB9vRjYRNU+9B+86
jHrN78jh07xFi7NgSXn+O0uOOyzXu0CqKz6m8+EGGwIDAQABoC8wLQYJKoZIhvcN
AQkOMSAwHjAcBgNVHREEFTATghFzZXJ2ZXIuZG9tYWluLmNvbTANBgkqhkiG9w0B
AQsFAAOCAQEAUDjC3ZGLCB32U90dcaPwYm3LmO/O+YmEIGVlVUp3Pd+fjvUXh313
8av4V1B3r4pifXyk7rIY8EAC/W4ukPXgBmdPXQvgY74O+NjU2QVaMkq6bOLEVOO3
C4A54r8DDAi/mCh7sMghQ2DRFtn4M4kw8KoCs6FMA5el0N/sAD6oIk/lyZnwDQlM
mH5MIjTaJH07saWnz3h3bzTOxJCpr58fMTAjMEPHZukqgCUL08PWTFWwbD69Kyer
ZpYt2jGAqUfwsczYPLg8qwy4fGhixiBJ515kLmH9iLOE2xKNcRtsQSrVFG4qNDo0
Q2FhHsOZpUMcSt57OSc5xnQ1aoyNujj83g==
-----END CERTIFICATE REQUEST-----
```