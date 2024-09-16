from tpm2_pytss import *

import random, string
def random_uid() -> str:
    """Generate a random id which can be used e.g. for unique key names."""
    return "".join(random.choices(string.digits, k=10))


FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321",temp_dirs=True, ek_cert_less='yes',profile_dir="./profiles")
fapi_ctx = FAPI()
fapi_ctx.provision()

print(str(fapi_ctx.get_random(8).hex()))

fapi_ctx.create_key(path='/HS/SRK/enc1', type_='decrypt', exists_ok=True)
e = fapi_ctx.encrypt(path='/HS/SRK/enc1', plaintext='foo')

print(e.hex())

d = fapi_ctx.decrypt(path='/HS/SRK/enc1', ciphertext=e)
print(d.decode('ascii'))


fapi_ctx.delete("/")
fapi_ctx.close()