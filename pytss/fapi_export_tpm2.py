from tpm2_pytss import *


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


## after running fapi_export_tpm2.py, you'll have /tmp/key.pub /tmp/key.priv which you can load with:

# tpm2_createprimary -C o -c /tmp/primary.ctx -Q
# tpm2_load -C /tmp/primary.ctx -u /tmp/key.pub -r /tmp/key.priv -c /tmp/key.ctx
# tpm2_flushcontext -t
# echo -n "fff" > message.dat
# tpm2_sign -c key.ctx -g sha256 -o sig.rssa message.dat -f plain
# xxd -p sig.rssa 


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321", temp_dirs=False, ek_cert_less='yes',
           system_dir="~/.local/share/tpm2-tss/system/keystore",
           profile_dir="/etc/tpm2-tss/fapi-profiles/",
           user_dir="~/.local/share/tpm2-tss/user/keystore/")

fapi_ctx = FAPI()
fapi_ctx.provision()

try:
    fapi_ctx.create_key(path='/HS/SRK/sign1', type_='sign', exists_ok=False)
except Exception as e:
  print(e)
  pass

l = fapi_ctx.list(search_path="/HS/")
print(l)

digest = sha256(b"fff")

sig, pub,cert = fapi_ctx.sign(path='/HS/SRK/sign1', digest=digest, padding="rsa_ssa")
print(sig.hex())
fapi_ctx.verify_signature(path='/HS/SRK/sign1', digest=digest, signature=sig)

pub, priv, pol = fapi_ctx.get_tpm_blobs(path='/HS/SRK/sign1')


with open("/tmp/key.pub", "wb") as binary_file:
    binary_file.write(pub.marshal())

with open("/tmp/key.priv", "wb") as binary_file:
    binary_file.write(priv.marshal())

## if you want, you can write the pub/priv to disk (eg pub.marshal())
# pub2, _ = TPM2B_PUBLIC.unmarshal(pub.marshal())
# priv2, _ = TPM2B_PRIVATE.unmarshal(priv.marshal())

#fapi_ctx.delete("/")
fapi_ctx.close()
