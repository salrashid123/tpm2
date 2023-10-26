#### Sealed Asymmetric Key with persistent files

Using ek public key to import an external RSA key and seal it into a TPM

basically [https://github.com/salrashid123/gcp_tpm_sealed_keys/tree/main#sealed-asymmetric-key](https://github.com/salrashid123/gcp_tpm_sealed_keys/tree/main#sealed-asymmetric-key) except that the public and private keys are saved externally (meaning it will survive a reboot).

fixes [https://github.com/google/go-tpm-tools/issues/349](https://github.com/google/go-tpm-tools/issues/349)

>> note this is a copy of : [https://github.com/salrashid123/gcp_tpm_sealed_keys/tree/main#sealed-asymmetric-key-with-persistent-files](https://github.com/salrashid123/gcp_tpm_sealed_keys/tree/main#sealed-asymmetric-key-with-persistent-files)

##### on laptop

The following program will seal and unseal an RSA key but critically, the imported RSA key on the tpm has the public/private key saved to files.

THis means the key can be reused after reboots easily.

```bash
gcloud compute instances get-shielded-identity instance-1 --format="value(encryptionKey.ekPub)" > /tmp/ek.pem

openssl genrsa -out /tmp/key.pem 2048
openssl rsa -in /tmp/key.pem -out /tmp/key_rsa.pem -traditional
```

##### Without PCR Policy


```bash
git clone https://github.com/salrashid123/gcp_tpm_sealed_keys.git

go run asymmetric/seal/main.go   \
     --rsaKeyFile=/tmp/key_rsa.pem  \
     --sealedOutput=sealsealed_no_pcred.dat  \
     --ekPubFile=/tmp/ek.pem \
      --v=10 -alsologtostderr

gcloud compute scp sealed_no_pcr.dat instance-1:/tmp/sealed_no_pcr.dat
```

##### on instance-1

```bash
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=import --pub pub.dat -priv priv.dat --importSigningKeyFile=sealed_no_pcr.dat   --flush=all
## by default the public/private references are saved to pub.dat and priv.dat

sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign --pub pub.dat -priv priv.dat  --flush=all

## reboot and read the pub.dat and priv.dat to sign data
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign --pub pub.dat -priv priv.dat  --flush=all
```


##### With PCR Policy

first alter the tpm's pcr value so we can test:

```bash
$ tpm2_pcrread sha256:23
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
    sha256:
      23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

on laptop

then seal to that pcr value

```bash 
git clone https://github.com/salrashid123/gcp_tpm_sealed_keys.git
go run asymmetric/seal/main.go   \
     --rsaKeyFile=/tmp/key_rsa.pem  \
     --sealedOutput=sealed_pcr.dat  --pcrValues=23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b   \
     --ekPubFile=/tmp/ek.pem \
      --v=10 -alsologtostderr

gcloud compute scp sealed_pcr instance-1:sealed_pcr.dat 
```

##### on instance-1

```bash
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=import --pub pub.dat -priv priv.dat --importSigningKeyFile=sealed_pcr.dat   --flush=all --bindPCRValues=23
## remember to set the pcr23 value forward
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign  --flush=all --pub pub.dat -priv priv.dat  --bindPCRValues=23
## reboot, remember to reset the pcr23 value forward
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign  --flush=all --pub pub.dat -priv priv.dat  --bindPCRValues=23
```