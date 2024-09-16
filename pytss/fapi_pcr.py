from tpm2_pytss import *

import random, string


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


def random_uid() -> str:
    """Generate a random id which can be used e.g. for unique key names."""
    return "".join(random.choices(string.digits, k=10))

FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321", temp_dirs=False, ek_cert_less='yes',
           system_dir="~/.local/share/tpm2-tss/system/keystore",
           profile_dir="./profiles",
           user_dir="~/.local/share/tpm2-tss/user/keystore/")

fapi_ctx = FAPI()
fapi_ctx.provision()


key_path= f"/HS/SRK/sign1111"

policy_path = f"/policy/pcr-policy"
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
fapi_ctx.import_object(path=policy_path, import_data=pcr_policy, exists_ok=True)
fapi_ctx.create_key(path=key_path, type_='sign', exists_ok=True, policy_path=policy_path)

l = fapi_ctx.list(search_path="/HS/")
print(l)

digest = sha256(b"fff")
sig, pub,cert = fapi_ctx.sign(path=key_path, digest=digest, padding="rsa_ssa")
print(sig.hex())


fapi_ctx.verify_signature(path=key_path, digest=digest, signature=sig)

#fapi_ctx.delete("/")
fapi_ctx.close()
