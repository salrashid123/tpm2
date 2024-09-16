from tpm2_pytss import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


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


def password_callback(path, descr, user_data):
    print(f"Callback: path={path}, descr={descr}, user_data={user_data}")
    return user_data

key_path= f"/HS/SRK/enc{random_uid()}"
fapi_ctx.create_key(path=key_path, type_='sign', exists_ok=True, auth_value="password")
fapi_ctx.set_auth_callback(password_callback, user_data=b"password")


digest = sha256(b"fff")
sig, pub,cert = fapi_ctx.sign(path=key_path, digest=digest, padding="rsa_ssa")
print(sig.hex())


key_path= f"/HS/SRK/enc{random_uid()}"
fapi_ctx.create_key(path=key_path, type_='decrypt', exists_ok=True, auth_value="password")
fapi_ctx.set_auth_callback(password_callback, user_data=b"password")
e = fapi_ctx.encrypt(path=key_path, plaintext='foo')
print(e.hex())
d = fapi_ctx.decrypt(path=key_path, ciphertext=e)
print(d.decode('ascii'))

