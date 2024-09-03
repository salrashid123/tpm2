## Python ESAPI and FAPI examples


Ref: 

* [https://tpm2-pytss.readthedocs.io/en/latest/api.html](https://tpm2-pytss.readthedocs.io/en/latest/api.html)
* [/P_RSA2048SHA256.json](https://github.com/tpm2-software/tpm2-tss/blob/master/dist/fapi-profiles/P_RSA2048SHA256.json)
* [fapi-config](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-config.md)

* [TSS_FAPI_v0p94_r09_pub.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TSS_FAPI_v0p94_r09_pub.pdf)
* [TSS_JSON_Policy_v0p7_r08_pub](https://trustedcomputinggroup.org/wp-content/uploads/TSS_JSON_Policy_v0p7_r08_pub.pdf)

#### Install

```bash
apt-get install libtss2-dev
python3 -m pip install tpm2-pytss
```


### ESAPI

- `esapi_create_sign.py`: create rsa key and sign/verify
- `esapi_encrypt_decrypt.py`: create aes key and encrypt/decrypt

- `fapi_create_sign.py`: create rsa key and sign/verify
- `fapi_seal_unseal.py`: seal/unseal 



### FAPI Session Encryption

From : [TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf)

```
• Application developers typically use the high-level TCG Feature API (FAPI) [3]. A compliant TSS
implementation of FAPI automatically encrypts commands and responses, and no work is required by
application developers.
```

