### EK-Based Key Attestation with TPM Firmware Version


Simple demo of [EK-Based Key Attestation with TPM Firmware Version](https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-Version-1_Pub.pdf)


![images/ek_attestation.png](images/ek_attestation.png)


```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"


$ go run main.go 
2026/05/04 06:44:33 ======= create ekPublic on Attestor  ========
2026/05/04 06:44:33 Name 000b53e7cbbd530a5c015a5dd1fd1b1a6795929a6c3150399577ca3c041111940988
2026/05/04 06:44:33 RSA EK createPrimary public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtPmTYabu0zFaOBJH7v8e
g6OsRnqmxGDaJ0kIsaCQ0VDd5iu1ChcJQ4Fij2zuDWCtgaGV4M27MxehE4YDKyiU
Dll85KACnDmO1mpguG3TBKfA/u1abfJNg2VGwnv4qJl7u7ZEAYFr1nTaQJ4hHIJo
2z7ndPAOCI6Zbq5557pGlm54qWiwYmHCbfLkPPW8M7SVZwPX201nbMipJ4BOxjgR
1x8RNFbuRN3wGCrj1ooZubkpVhUU6uTsTMyuF1/L+6XtEomX1UxWoeMJKb6v1rvh
hH4SUNMBFem/7wag7YwW6ISkvnawC7b8xsr0/KwMAoul9KK6j2w63A2hRu0vUMj4
kwIDAQAB
-----END PUBLIC KEY-----

2026/05/04 06:44:33 ======= send the ekPub.PEM to the Verifier ========
2026/05/04 06:44:33 ======= create a random HMAC key and duplicate it ========
duplicateTemplate Name 000b9bf0387da7c9c6f492863881ecd1957840bd1f179b6e850c86c9b693aa1e7882
2026/05/04 06:44:33 ======= verifier sends duplicate key, duplicate seed and duplicate pub to Attestor ========
2026/05/04 06:44:33 ======= Attestor creates  EK ========
2026/05/04 06:44:33 ======= Attestor imports the duplicated hmac key ========
2026/05/04 06:44:33 ======= Attestor creates AK ========
2026/05/04 06:44:33 Created AK Name :000b77a47fcc7f92f3c25e961ab6b41731b25fedc459a39fb72440e446b6746366e4
2026/05/04 06:44:33 AK RSA Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAschZiBg27V7ye8t+UxJ2
rObTW+sxu6Jm0o3eWeaVUSTNkwFpCNYBkcp9Lh8J5ZDCm6Re8zJvgQ9NacGkVKSG
ZkHM3w1Pw1bJIaAejRTYlnM35kNarFKc/KxJdYZ1AEp06fBL8FBCRUTdu5tc7z2W
KdUnKmcKuAQW5c2b+4u7VxC68Jmv57D7Zn2zHVmYvViXySfNkFmjR3ZCP6SRUXq8
ZFybyHSPujR5cWQbp8UdEpwmRA7Go6Y7bAn4pGJjv1U3Q1e09jnIn+DMoyeQ1NQc
R9C0C5jcmwKJmzfG258hJeU+h3qITbxfniAq8AUHH0PbbaqSGjhObqIz3f52qIa+
OQIDAQAB
-----END PUBLIC KEY-----

2026/05/04 06:44:33 ======= Attestor certifies ak with the duplicated key ========
2026/05/04 06:44:33 ======= Attestor sends attestation signature,attestation and the AK RSA Public key (akPubPEM) to Verifier ========
2026/05/04 06:44:33 Certify Response digest 0CfGkjpJhCCB5ALz6SVhy440VP/d9em5xZz3qx93pTE=
2026/05/04 06:44:33 ======= verifier checks attesatation certification info specifications ========
2026/05/04 06:44:33      Certify Firmware Version  Major 8228
2026/05/04 06:44:33      Certify Firmware Version  Minor 293
2026/05/04 06:44:33      Certify Firmware Version  Build 18
2026/05/04 06:44:33      Certify Firmware Version  Revision 0
2026/05/04 06:44:33      Attestation FirmwareVersion 2315977366801874944
2026/05/04 06:44:33 Certify AK Name 000b77a47fcc7f92f3c25e961ab6b41731b25fedc459a39fb72440e446b6746366e4
2026/05/04 06:44:33 Certify Extra Data 
2026/05/04 06:44:33 Derived Name from rsa PublicKey 000b77a47fcc7f92f3c25e961ab6b41731b25fedc459a39fb72440e446b6746366e4
2026/05/04 06:44:33 Attesation names match
2026/05/04 06:44:33 ======= Attestor verifies the HMAC signature of the attesation certification info  ========
2026/05/04 06:44:33 calculated hmac of attestation using local hmac key 0CfGkjpJhCCB5ALz6SVhy440VP/d9em5xZz3qx93pTE=
2026/05/04 06:44:33 attestation verified

```

```bash
$ tpm2_getcap  properties-fixed

TPM2_PT_FIRMWARE_VERSION_1:
  raw: 0x20240125             // bigendian  major 8228  minor 293
TPM2_PT_FIRMWARE_VERSION_2:
  raw: 0x120000
```

