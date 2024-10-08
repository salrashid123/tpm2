from tpm2_pytss import *

import random, string
def random_uid() -> str:
    """Generate a random id which can be used e.g. for unique key names."""
    return "".join(random.choices(string.digits, k=10))


FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321", temp_dirs=False, ek_cert_less='yes',
           system_dir="~/.local/share/tpm2-tss/system/keystore",
           profile_dir="./profiles",
           user_dir="~/.local/share/tpm2-tss/user/keystore/")

fapi_ctx = FAPI()
fapi_ctx.provision()

seal_data = "secret".encode()

policy_path= f"/policy{random_uid()}"
key_path= f"/HS/SRK/key{random_uid()}"

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
fapi_ctx.import_object(path=policy_path, import_data=pcr_policy)

success = fapi_ctx.create_seal(path=key_path, data=seal_data,  policy_path=policy_path)

print(success)

# pcr_data = b"abc"
# pcr_digest = sha256(pcr_data)
# fapi_ctx.pcr_extend(index=0,data=pcr_digest)

unsealed_data = fapi_ctx.unseal(path=key_path)

print(unsealed_data.decode('ascii'))

# fapi_ctx.delete("/")
fapi_ctx.close()