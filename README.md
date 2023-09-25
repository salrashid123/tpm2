# Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm

Just some sample common flows for use with TPM modules and libraries.

The primary focus is how use `tpm2_tools` to perform common tasks that i've come across.

Also shown equivalent use of `go-tpm` library set.


- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
- [go-tpm](https://github.com/google/go-tpm)
- [go-tpm-tools](https://github.com/google/go-tpm-tools)
- [go-attestation](https://github.com/google/go-attestation)



Update 8/28/21:  Added a gRPC client/server that does full remote attestation, quote/verify and secret sharing:

- [https://github.com/salrashid123/go_tpm_remote_attestation](https://github.com/salrashid123/go_tpm_remote_attestation)

## Usecases:

- `encrypt_with_tpm_rsa`: Encrypt with RSA Key generated on TPM (`tpm2_create`, `tpm2_rsaencrypt, tpm2_decrypt`)

- `chained_keys`: Encrypt/Decrypt using parent->child->child keys

- `gcp_ek_ak`: read gcp ek keys from NV using go-tpm-tools and gcloud API

- `ek_import_blob`: Seal data using a _real_ tpm's ekcert signed by Optiga

- `tpm_quote_verify`: Generate TPM Quote blob with PCR23 value (`tpm2_createak`, `tpm2_quote`, `tpm2_checkquote`)

- `event_log`: Generate and Verify a TPM [event log]()

- `srk_seal_unseal`: Seal arbitrary data directly to TPM; use PCR Policy (`tpm2_create`, `tpm2_load`, `tpm2_seal`, `tpm2_unseal`)

- `sign_with_ak`: Sign with Attestation Key (`tpm2_createak`, `tpm2_hash`, `tpm2_sign`, `tpm2_verifysignature`)

- `sign_certify_ak`:  Generate Child key and Sign data with it.  Create Attestation/[Certify](https://godoc.org/github.com/google/go-tpm/tpm2#Certify) child key with AK.  Verify Signature.

- `sign_wth_rsa`: Generate RSA key with TPM  and sign (`tpm2_create`,`tpm2_load`, `tpm2_sign`, `tpm2_verifysignature`)

- `tpm_import_external_rsa`: Import external RSA key to TPM; decrypt data with TPM (`tpm2_import, tpm2_load, tpm2_rsadecrypt`)

- `tpm_make_activate`: Attestation Protocol using Make-Activate credentials (`tpm2_makecredential`, `tpm2_activatecredential`)

- `tpm2_get_ak_name`: Gets the AK "name" given the PEM format of a public key.

- `tpm2_duplicate`: Use (`tpm2_import`, `tpm2_duplicate`) encrypt and transfer a key from one TPM to another.

- `hmac_import`: Import an external hmac key and use it to do hmac-stuff

- `tpm_services`: samples in go for  standalone remote attestation, quote-verify and seal-unseal

- `ek_import_blob`: Transfer secret  using ekPub only. Example only covers `go-tpm` based transfer (TODO: figure out the `tpm2_tools` flow).
      * see  to [https://github.com/salrashid123/gcp_tpm_sealed_keys](https://github.com/salrashid123/gcp_tpm_sealed_keys) 

- `ek_import_rsa_blob`: Transfer RSA key from your local system to a GCP vTPM using its ekPub only. Example only covers `go-tpm` based transfer.  For example, use this mechanism to transfer a Service Account Private key securely such that the key on the vTPM cannot be exported but yet available to sign and authenticate.
      * see  to [https://github.com/salrashid123/gcp_tpm_sealed_keys](https://github.com/salrashid123/gcp_tpm_sealed_keys)

- `utils`:  Utility functions
    - Convert PEM formatted key to TPM2-tools format.

- `mTLS`:  mTLS using `go-tpm` and nginx

- `ima_policy`:  Sample 'helloworld' configuration of IMA.

- `pcr_utils`:  Read and Extend PCR values

- `PKCS11`:  Access TPM using PKCS-11 and openssl

- `LUKS`:  Use TPM for LUKS encryption

- `attest_verify`: remote attestation using `go-tpm-tools`

- `ak_sign_nv`: read Attestation Key from NV index, sign and verify for Google Compute Engine VMs

- `context_chain`:  create parent, child, grandchild keys

- `resource_manager`:  `tpm0`` vs `tpmrm0`

### Usage

Excercising any of the scenarios above requires access to a TPM(!).  You can use `vTPM` included with a Google Cloud [Shielded VM](https://cloud.google.com/shielded-vm/) surfaced at `/dev/tpm0` on the VM

#### Create test VM with TPM

```
 gcloud  compute  instances create shielded-1 --zone=us-central1-a --machine-type=n1-standard-1 --no-service-account --no-scopes --image=ubuntu-1804-bionic-v20191002 --image-project=gce-uefi-images --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

> note, you may need to update `--image=`

#### Installing tpm2_tools, golang

- Install golang

- Install `tpm2_tools`:

  - [tpm2-tss/INSTALL](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md)
  - [tpm2-tools/INSTALL](https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md)

either from debian-testing

```
$ vi /etc/apt/sources.list
  deb http://http.us.debian.org/debian/ testing non-free contrib main


$ export DEBIAN_FRONTEND=noninteractive 
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc -y

```

or from source:

```bash
apt-get update

apt -y install   autoconf-archive   libcmocka0   libcmocka-dev   procps   iproute2   build-essential   git   pkg-config   gcc   libtool   automake   libssl-dev   uthash-dev   autoconf   doxygen  libcurl4-openssl-dev dbus-x11 libglib2.0-dev libjson-c-dev acl
```

```bash
cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig
```

```bash
cd
git clone https://github.com/tpm2-software/tpm2-tools.git
  cd tpm2-tools
  ./bootstrap
  ./configure
  make check
  make install
```


#### Install tpm2-tss openssl engine

This step is optional an only do this if you intend to use openssl w/ the TPM as the `engine`


```bash
cd
git clone https://github.com/tpm2-software/tpm2-tss-engine.git
  cd tpm2-tss-engine
  ./bootstrap
  ./configure
  make -j$(nproc)
  sudo make install
```

Check if openssl works w/ tpm2 (optional)
```bash
$ openssl engine -t -c tpm2tss
    (tpm2tss) TPM2-TSS engine for OpenSSL
    [RSA, RAND]
        [ available ]
```

#### Non-root access to in-kernel resource manager `/dev/tpmrm0` usint tpm2-tss

For non-root access using tss resource manager

* [tpm-udev.rules](https://github.com/tpm2-software/tpm2-tss/blob/master/dist/tpm-udev.rules)

```bash
# cat /etc/udev/rules.d/tpm-udev.rules 
# tpm devices can only be accessed by the tss user but the tss
# group members can access tpmrm devices
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", OWNER="tss"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
```

```bash
sudo usermod -a -G tss $USER
newgrp tss
```

#### Clear TPM objects/sessions
```bash
        tpm2_flushcontext --loaded-session
        tpm2_flushcontext --saved-session
        tpm2_flushcontext --transient-object
```


### mTLS with TPM

Git repo demonstrating running mTLS using go-tpm and nginx webserver:

- [golang TLS with Trusted Platform Module (TPM) based keys](https://github.com/salrashid123/go_tpm_https)


### Appendix


#### Envelope encryption using openssl

```bash
KEK: Asymmetric
DEK: Symmetric
    openssl genrsa -out KEK.pem 2048
    openssl rsa -in KEK.pem -outform PEM -pubout -out KEK_PUBLIC.pem
    echo "thepassword" > secrets.txt

    openssl rand 32 > DEK.key
    openssl enc -aes-256-cbc -salt -pbkdf2 -in secrets.txt -out secrets.txt.enc -pass file:./DEK.key

    openssl rsautl -encrypt -inkey KEK_PUBLIC.pem -pubin -in DEK.key -out DEK.key.enc

    openssl rsautl -decrypt -inkey KEK.pem -in DEK.key.enc -out DEK.key.ptext
    openssl enc -d -aes-256-cbc -pbkdf2 -in secrets.txt.enc -out secrets.txt.ptext  -pass file:./DEK.key.ptext
    more secrets.txt.ptext

KEK: Symmetric
DEK: Symmetric
    openssl rand 32 > kek.key
    openssl rand 32 > dek.key

    openssl enc -pbkdf2 -in secrets.txt -out secrets.txt.enc -aes-256-cbc -pass file:./dek.key
    openssl enc -pbkdf2 -in dek.key -out dek.key.enc -aes-256-cbc --pass file:./kek.key

    openssl enc -d -aes-256-cbc -pbkdf2 -in dek.key.enc -out dek.key.ptext  -pass file:./kek.key
    openssl enc -d -aes-256-cbc -pbkdf2 -in secrets.txt.enc -out secrets.txt.ptext  -pass file:./dek.key.ptext

```

#### References/Links

- [The Trusted Platform Module Key Hierarchy](https://ericchiang.github.io/post/tpm-keys/)
- [googe cloud credentials TPMTokenSource](https://github.com/salrashid123/oauth2#tpmtokensource)
- [TPM2-TSS-Engine hello world and Google Cloud Authentication](https://github.com/salrashid123/tpm2_evp_sign_decrypt)

- [https://www.scribd.com/document/398036850/2015-Book-APracticalGuideToTPM20](https://www.scribd.com/document/398036850/2015-Book-APracticalGuideToTPM20)
- [https://google.github.io/tpm-js](https://google.github.io/tpm-js)
- [https://www.tonytruong.net/how-to-use-the-tpm-to-secure-your-iot-device-data/](https://www.tonytruong.net/how-to-use-the-tpm-to-secure-your-iot-device-data/)
- [https://github.com/tpm2-software/tpm2-tools/wiki/Creating-Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Creating-Objects)
- [https://dguerriblog.wordpress.com/2016/03/03/tpm2-0-and-openssl-on-linux-2/](https://dguerriblog.wordpress.com/2016/03/03/tpm2-0-and-openssl-on-linux-2/)
- [https://courses.cs.vt.edu/cs5204/fall10-kafura-BB/Papers/TPM/Intro-TPM-2.pdf](https://courses.cs.vt.edu/cs5204/fall10-kafura-BB/Papers/TPM/Intro-TPM-2.pdf)
