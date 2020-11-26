
## PKCS11 example using GCP Shielded VM

The following will setup tpm2-pkcs11 support for GCP vTPM

At the time of writing [https://github.com/tpm2-software/tpm2-pkcs11](https://github.com/tpm2-software/tpm2-pkcs11) is not yet on debian stable so we have to use testing.

- Setup

Create a  GCP Shielded VM and ssh into it

```bash
gcloud compute  instances create   tpm-pkcs    --zone=us-central1-a --machine-type=n1-standard-1    --tags tpm      --no-service-account  --no-scopes      --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring     --image=debian-10-buster-v20200805 --image-project=debian-cloud

gcloud compute ssh tpm-pkcs
```

Then on the VM

```bash
$ vi /etc/apt/sources.list
  deb http://http.us.debian.org/debian/ testing non-free contrib main


$ export DEBIAN_FRONTEND=noninteractive 
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc -y


# create alias that specifies the module to use
$ alias tpm2pkcs11-tool="pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1"

# initialize slot0 as token1
$ tpm2pkcs11-tool --slot-index=0 --init-token --label="token1" --so-pin="mysopin"

    Using slot with index 0 (0x1)
    Token successfully initialized

# change the pin 
$ tpm2pkcs11-tool --label="token1" --init-pin --so-pin mysopin --pin mynewpin
    Using slot 0 with a present token (0x1)
    User PIN successfully initialized


$ tpm2pkcs11-tool --list-token-slots
    Available slots:
    Slot 0 (0x1): token1                          GOOG
    token label        : token1
    token manufacturer : GOOG
    token model        : vTPM
    token flags        : login required, rng, token initialized, PIN initialized
    hardware version   : 1.42
    firmware version   : 22.17
    serial num         : 0000000000000000
    pin min/max        : 0/128
    Slot 1 (0x2):                                 GOOG
    token state:   uninitialized

# create a keypair

$ tpm2pkcs11-tool --label="keylabel1" --login --pin=mynewpin --keypairgen
    Using slot 0 with a present token (0x1)
    Key pair generated:
    Private Key Object; RSA 
    label:      keylabel1
    Usage:      decrypt, sign
    Access:     sensitive, always sensitive, never extractable, local
    Allowed mechanisms: RSA-X-509,RSA-PKCS-OAEP,RSA-PKCS,SHA1-RSA-PKCS,SHA256-RSA-PKCS,SHA384-RSA-PKCS,SHA512-RSA-PKCS,RSA-PKCS-PSS
    Public Key Object; RSA 2048 bits
    label:      keylabel1
    Usage:      encrypt, verify
    Access:     local

# create random text
$ tpm2pkcs11-tool --label="keylabel1" --pin mynewpin --generate-random 50 | xxd -p
    Using slot 0 with a present token (0x1)
    976553b6
```

Configure openssl defaults edit `/etc/ssl/openssl.cnf`
add at to TOP 

```conf
openssl_conf = openssl_def
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1
```

Specify the PKCS URL and use the TPM keys to sign/verify
```bash

export PKCS11_PRIVATE_KEY="pkcs11:model=vTPM;manufacturer=GOOG;serial=0000000000000000;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_PUBLIC_KEY="pkcs11:model=vTPM;manufacturer=GOOG;serial=0000000000000000;token=token1;type=public;object=keylabel1?pin-value=mynewpin"


echo "sig data" > "data.txt"

openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig



openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout
    engine "pkcs11" set.
    writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA104io9zq+GXDm3VPPDt5
h6CNVB/ckkx7mH0xC+xuUGDU1VwU54MYpQWGNPAsbDUS1r2Ai9Si1mtST6A5eV3q
hBkQu1PJAAfKfG38k2uZa2vHKx6KiVUTsnUYZp1R6Sfahtf2iPoQ+MFILAIlMoth
8ykN9KP9jBxVWDOCOyDfDJkGVWPKaUNIUn4Yb1OilzJnE9BIZd5cmelPI43pFTRo
CrInLCNsoUgvZdXBrrW7IKl/6zP59K7vcjsjSr0nQ0S7gKdhYswXKAm2YALoECe2
W7Iff9tMpTt3jubu7cFH4jKXqso0lAagtaBre+BOfNs5QrZhk8Po/xixbfFqEz30
AwIDAQAB
-----END PUBLIC KEY-----

```