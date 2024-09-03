from tpm2_pytss import *
FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321",temp_dirs=True, ek_cert_less='yes',profile_dir="./profiles")
fapi_ctx = FAPI()
fapi_ctx.provision()
print(str(fapi_ctx.get_random(8).hex()))
fapi_ctx.create_key(path='/HS/SRK/enc1', type_='decrypt', exists_ok=True)
e = fapi_ctx.encrypt(path='/HS/SRK/enc1', plaintext='foo')
print(e.hex())
d = fapi_ctx.decrypt(path='/HS/SRK/enc1', ciphertext=e)
print(d.decode('ascii'))


seal_data = "secret".encode()
path = f"/HS/SRK/seal_obj"

pcr_policy="""{
    "description":"Policy PCR 0 TPM2_ALG_SHA256",
    "policy":[
        {
            "type":"POLICYPCR",
            "pcrs":[
                {
                    "pcr":0,
                    "hashAlg":"TPM2_ALG_SHA256",
                    "digest":"0000000000000000000000000000000000000000000000000000000000000000"
                }
            ]
        }
    ]
}

"""
fapi_ctx.import_object(path="/policy/pcr-policy", import_data=pcr_policy)
success = fapi_ctx.create_seal(path=path, data=seal_data,  policy_path="/policy/pcr-policy")

print(success)

# pcr_data = b"abc"
# pcr_digest = sha256(pcr_data)
# fapi_ctx.pcr_extend(index=0,data=pcr_digest)

unsealed_data = fapi_ctx.unseal(path=path)

print(unsealed_data.decode('ascii'))

fapi_ctx.delete("/")
fapi_ctx.close()