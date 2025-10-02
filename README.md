# Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm

Just some sample common flows for use with TPM modules and libraries.

The primary focus is how use `tpm2_tools` to perform common tasks that i've come across.

Also shown equivalent use of `go-tpm` library set.

for the `go-tpm` examples, i am slowly migrating them over to the [go-tpm direct](https://github.com/google/go-tpm/releases/tag/v0.9.0) API.  If you would rather use the legacy version, just check the commit history to maybe a snapshot at July 2024.

---

### Related items

### Key transfer

* [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)
* [Go-TPM-Wrapping - Go library for encrypting data using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)
* [TINK Go TPM extension](https://github.com/salrashid123/tink-go-tpm/)
* [Transferring RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys)
* [tpm2genkey go utility](https://github.com/salrashid123/tpm2genkey)
* [OCICrypt provider for Trusted Platform Modules (TPM)](https://github.com/salrashid123/ocicrypt-tpm-keyprovider)

### go library

* [TPM backed crypto/rand Reader](https://github.com/salrashid123/tpmrand)
* [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)
* [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)

### Cloud Authentication

For authentication using TPM based keys to cloud providers

* [Cloud Auth Library using Trusted Platform Module (TPM)](https://github.com/salrashid123/cloud_auth_tpm)

* `AWS HMAC`:  [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac)
* `AWS Roles Anywhere`: [AWS SDK CredentialProvider for RolesAnywhere](https://github.com/salrashid123/aws_rolesanywhere_signer)
* `AWS TPM process credentials`: [AWS Process Credentials for Trusted Platform Module (TPM)](https://github.com/salrashid123/aws-tpm-process-credential)

* `Azure` [KMS, TPM and HSM based Azure Certificate Credentials](https://github.com/salrashid123/azsigner)

* `GCP Credential Source Binary`: [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
* `GCP TokenSource`: [GCP TPM AccessTokenSource](https://github.com/salrashid123/oauth2?tab=readme-ov-file#usage-tpmtokensource)

### Kubernetes

* [Kubernetes Trusted Platform Module (TPM) DaemonSet](https://github.com/salrashid123/tpm_daemonset)
* [Kubernetes Trusted Platform Module (TPM) using Device Plugin and Gatekeeper](https://github.com/salrashid123/tpm_kubernetes)

### TLS examples

* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [TPM based TLS using Attested Keys (experimental)](https://github.com/salrashid123/tls_ak)
* [TPM One Time Password using TLS SessionKey](https://github.com/salrashid123/tls_tpm_one_time_password)

---

Additional References:

- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
- [go-tpm](https://github.com/google/go-tpm)
- [go-tpm-tools](https://github.com/google/go-tpm-tools)
- [go-attestation](https://github.com/google/go-attestation)

    Simple cli utility similar to [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md) which 

    * creates new TPM-based `RSA|ECC` keys and saves the keys in `PEM` format.
    * converts basic the public/private keyfiles generated using `tpm2_tools` into `PEM` file format.
    * converts `PEM` TPM keyfiles to public/private structures readable by `tpm2_tools`.

- [tpm-js simulator](https://google.github.io/tpm-js/)


- [Trusted Platform Module Library Part 1: Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf)
- [Trusted Platform Module Library Part 2: Structures](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
- [Trusted Platform Module Library Part 3: Commands](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)
- [Trusted Platform Module Library Part 4: Supporting Routines](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf)

- [CPU to TPM Bus Protection Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf)

---

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

- `sign_wth_ecc`: Generate ECC key with TPM  and sign, verify

- `encrypte_decrypt_aes`:  encrypt and decrypt with aes key on tpm

- `keyfile-go-tpm-tools`: use go-tpm's direct api with `go-tpm-keyfiles` and `go-tpm-tools.client.Key` 

- `simulator_swtpm_tcpdump`: run a software tpm locally use tcpdump to decode traffic with wireshark

- `tpm_encrypted_session`: demonstrate session encryption to protect cpu->tpm bus interface

- `password`: Encrypt/Decrypt with passwords on parent and key

- `h2_primary_template`: using the H2 primary key template

- `rsa_import`: Import external RSA key to TPM; decrypt data with TPM (`tpm2_import, tpm2_load, tpm2_rsadecrypt`)

- `ecc_import`: Import external ECC key to TPM; decrypt data with TPM (`tpm2_import, tpm2_load, tpm2_rsadecrypt`)

- `tpm_make_activate`: Attestation Protocol using Make-Activate credentials (`tpm2_makecredential`, `tpm2_activatecredential`)

- `tpm2_get_ak_name`: Gets the AK "name" given the PEM format of a public key.

- `tpm2_duplicate`: Use (`tpm2_import`, `tpm2_duplicate`) encrypt and transfer a key from one TPM to another.

- `tpm2_duplicate_direct`:  duplicate an rsa key to `TPM-B` manually (i.,e without `TPM-A`)

- `tpm2_duplicate_go`: Duplicate HMAC key from one tpm to another using go-tpm's direct API.  Also calculate HMAC in go using the TPM

- `hmac_import`: Import an external hmac key and use it to do hmac-stuff

- `hmac_import`: Import an external aes key and use it to do hmac-stuff

- `policy`: Samples covering using session policy (pcr, policysigned, password, authvalue)

- `policy_gen`: Extract and use the raw low-level policy command parameters

- `tpm_services`: samples in go for  standalone remote attestation, quote-verify and seal-unseal

- `ek_import_blob`: Transfer secret  using ekPub only. Example only covers `go-tpm` based transfer (TODO: figure out the `tpm2_tools` flow).
      * see  to [https://github.com/salrashid123/gcp_tpm_sealed_keys](https://github.com/salrashid123/gcp_tpm_sealed_keys) 

- `ek_import_rsa_blob`: Transfer RSA key from your local system to a GCP vTPM using its ekPub only. Example only covers `go-tpm` based transfer.  For example, use this mechanism to transfer a Service Account Private key securely such that the key on the vTPM cannot be exported but yet available to sign and authenticate.
      * see  to [https://github.com/salrashid123/gcp_tpm_sealed_keys](https://github.com/salrashid123/gcp_tpm_sealed_keys)

- `mTLS`:  mTLS using `go-tpm` and nginx

- `ima_policy`:  Sample 'helloworld' configuration of IMA.

- `pcr_utils`:  Read and Extend PCR values

- `PKCS11`:  Access TPM using PKCS-11 and openssl

- `LUKS`:  Use TPM for LUKS encryption

- `attest_verify`: remote attestation using `go-tpm-tools`

- `ak_sign_nv`: read Attestation Key from NV index, sign and verify for Google Compute Engine VMs

- `context_chain`:  create parent, child, grandchild keys

- `resource_manager`:  `tpm0`` vs `tpmrm0`

- `kdf`:  Key Derivation Functions (KDF) based on the recommendations of NIST SP 800-108 using TPM baced HMAC

- `tpm_remote`: Connect to a remote TPM over inscure TCP  socket


---

### Software TPM

If you want to test locally with a software tpm ([swtpm](https://github.com/stefanberger/swtpm)), install the swtpm and launch.

Just note that AFAIK, the swtpm does *not* have a resrouce manager so you'll have to run `tpm2_flushcontext -t` a lot...


- `swtpm socket`

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
   swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
   swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

export TPM2TOOLS_TCTI="swtpm:port=2321"
```


- `swtpm socket` with `socat`

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
   swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
   swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

sudo socat pty,link=/tmp/vtpm,raw,echo=0 tcp:localhost:2321
sudo chmod go+rw /tmp/vtpm

export TPM2TOOLS_TCTI="device:/tmp/vtpm"
```

- `swtpm chardev`

TODO:, 


---


### Usage

Excercising any of the scenarios above requires access to a TPM(!).  You can use `vTPM` included with a Google Cloud [Shielded VM](https://cloud.google.com/shielded-vm/) surfaced at `/dev/tpmrm0` on the VM

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

## to enable tss debug, set
### export TSS2_LOG=esys+debug
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


#### Install tpm2-tss openssl engine (openssl1.x)

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

```bash

export OPENSSL_CONF=/path/to/openssl.cnf

$ openssl engine -t
(rdrand) Intel RDRAND engine
     [ available ]
(dynamic) Dynamic engine loading support
     [ unavailable ]
(tpm2tss) TPM2-TSS engine for OpenSSL
     [ available ]
```
- `openssl.cnf`
  
```conf
[openssl_init]
engines = engine_section

[engine_section]
tpm2tss = tpm2tss_section

[tpm2tss_section]
engine_id = tpm2tss
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/libtpm2tss.so
default_algorithms = RSA,ECDSA
init = 1
```

#### Install tpm2-openssl provider (openssl3)

for openssl3 [tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl) installed:

```bash
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/   # or wherever tpm2.so sits, eg /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so

$ openssl version
   OpenSSL 3.0.9 30 May 2023 (Library: OpenSSL 3.0.9 30 May 2023)

$ openssl list --providers -provider tpm2
Providers:
  tpm2
    name: TPM 2.0 Provider
    version: 1.2.0-25-g87082a3
    status: active
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


### TPM based private key

If you have openssl and want to issue a cert on the TPM, 

using openssl3 [tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl) installed:

```bash

openssl version
   OpenSSL 3.0.9 30 May 2023 (Library: OpenSSL 3.0.9 30 May 2023)

export NAME=tpms
export TSS2_LOG=esys+debug

openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out certs/$NAME.key

openssl req -new  -provider tpm2 -provider default \
      -config server.conf   -out certs/$NAME.csr \
          -key certs/$NAME.key   -subj "/C=US/O=Google/OU=Enterprise/CN=server.domain.com"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions server_ext
```

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
