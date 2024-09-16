from tpm2_pytss import *

import base64
import json
from datetime import datetime, timedelta

import random, string
def random_uid() -> str:
    """Generate a random id which can be used e.g. for unique key names."""
    return "".join(random.choices(string.digits, k=10))


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

key_path= f"/HS/SRK/key{random_uid()}"

FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321", temp_dirs=False, ek_cert_less='yes',
           system_dir="~/.local/share/tpm2-tss/system/keystore",
           profile_dir="./profiles",
           user_dir="~/.local/share/tpm2-tss/user/keystore/")

fapi_ctx = FAPI()
fapi_ctx.provision()

# $ tpm2_createprimary -C o -c primary.ctx 
# name-alg:
#   value: sha256
#   raw: 0xb
# attributes:
#   value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt
#   raw: 0x30072
# type:
#   value: rsa
#   raw: 0x1
# exponent: 65537
# bits: 2048
# scheme:
#   value: null
#   raw: 0x10
# scheme-halg:
#   value: (null)
#   raw: 0x0
# sym-alg:
#   value: aes
#   raw: 0x6
# sym-mode:
#   value: cfb
#   raw: 0x43
# sym-keybits: 128


# tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx -Q
# tpm2_flushcontext -t
# tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# tpm2_flushcontext -t

# $ echo '{"public":"'`xxd -p -c 1000 key.pub`'", "private": "'`xxd -p -c 1000 key.priv`'", "noauth":"YES"}' | jq '.'
# {
#   "public": "01180001000b00040072000000100014000b0800000000000100c4e9061e188c90f05a92a7820d91e8dcc3bbd784f738a0acc21dd3249940e001ef926dac486ba429f50d6c76b82013bbcc066cc1f54019182ff33d13da3c9962930dff3a0b55d775a9087b36ab7248a801abb8905097c61718959184c877a24d4aab00196bf2204d8eb5b856418ce78a382611904249c4309798240519dd21495b32450ba91c6dad7e09fd74c560382819cca9f96f8c8cb201ef274147e85d4f680b7ec2e32a54bdc1010cf7188415cd36a7575c7ef6569b1d7f2cd0bd993e2546a1617ffeb1f21015a015f2ebeff39d3da311917b3d6cdc5e8dbdb3e2725e45166cf3f3f93371b99a072d33d2ca0db1ad37cef2159bb83493df6dadaa5c1a4b",
#   "private": "00de002085ba735dd632280c670e2731b018e8faf221209e8784bea712b1e5578db076aa0010174bd9ceb675c5dbedb1fbc79533c6a6206d8e7f56a92cfb2a90e350484f25a1a0add8f939d5459d6d5c52c415fa4b1ad16da009abe2102d5a59a1283ab16f195d3bd4a04304a444a16c9eb5d81a80071cbef97ec4182f51ebc049341833432106c9508c1a4244559bc6d94feb1003d89873d24a149e8fe9e828fa4f72f6e64f70d82a3a1eb46b18723064cd884a3866e45e33cfdc1cf100d569baf2f8e99171ec9873cc2a2a7730e501856fce4e0bf251782ddcfcd341e4feac",
#   "noauth": "YES"
# }

### important: replace with the pub/priv from your tpm
key = """{
  "public": "01180001000b00040072000000100014000b0800000000000100c4e9061e188c90f05a92a7820d91e8dcc3bbd784f738a0acc21dd3249940e001ef926dac486ba429f50d6c76b82013bbcc066cc1f54019182ff33d13da3c9962930dff3a0b55d775a9087b36ab7248a801abb8905097c61718959184c877a24d4aab00196bf2204d8eb5b856418ce78a382611904249c4309798240519dd21495b32450ba91c6dad7e09fd74c560382819cca9f96f8c8cb201ef274147e85d4f680b7ec2e32a54bdc1010cf7188415cd36a7575c7ef6569b1d7f2cd0bd993e2546a1617ffeb1f21015a015f2ebeff39d3da311917b3d6cdc5e8dbdb3e2725e45166cf3f3f93371b99a072d33d2ca0db1ad37cef2159bb83493df6dadaa5c1a4b",
  "private": "00de002085ba735dd632280c670e2731b018e8faf221209e8784bea712b1e5578db076aa0010174bd9ceb675c5dbedb1fbc79533c6a6206d8e7f56a92cfb2a90e350484f25a1a0add8f939d5459d6d5c52c415fa4b1ad16da009abe2102d5a59a1283ab16f195d3bd4a04304a444a16c9eb5d81a80071cbef97ec4182f51ebc049341833432106c9508c1a4244559bc6d94feb1003d89873d24a149e8fe9e828fa4f72f6e64f70d82a3a1eb46b18723064cd884a3866e45e33cfdc1cf100d569baf2f8e99171ec9873cc2a2a7730e501856fce4e0bf251782ddcfcd341e4feac",
  "noauth": "YES"
}
"""
fapi_ctx.import_object(path=key_path, import_data=key,exists_ok=False)

def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


l = fapi_ctx.list(search_path="/HS/")
print(l)

digest = sha256(b"fff")

sig, pub,cert = fapi_ctx.sign(path=key_path, digest=digest, padding="rsa_ssa")
print(sig.hex())

fapi_ctx.verify_signature(path=key_path, digest=digest, signature=sig)

#fapi_ctx.delete("/")
fapi_ctx.close()