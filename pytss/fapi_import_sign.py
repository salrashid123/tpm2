from tpm2_pytss import *


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import random, string
def random_uid() -> str:
    """Generate a random id which can be used e.g. for unique key names."""
    return "".join(random.choices(string.digits, k=10))


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest

FAPIConfig(profile_name='P_RSA2048SHA256',tcti="swtpm:port=2321", temp_dirs=False, ek_cert_less='yes',
           system_dir="~/.local/share/tpm2-tss/system/keystore",
           profile_dir="./profiles",
           user_dir="~/.local/share/tpm2-tss/user/keystore/")

fapi_ctx = FAPI()
fapi_ctx.provision()

key_path= f"/HS/SRK/key{random_uid()}"
try:
    key_private_pem="-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOHW00xKYNp0xv\ngbUDbedDyGDV6dM54TIBEiVZ0PPldACI6YBt8n+N5EnrrzkxEOEqTBQduhIQaGpe\nAgigU9MZPw1o1974Se7FIjRJA9nrvAkT2uEGAfq8wFgFnTvH7NbROGyaMEiwoAGI\nKAZfyXJ7Np095eLHSBx8xyP/j1OtrWw6M/duPR30X4bXdEZ8xbNbMsaz7+rYhuuU\n5XtUzJ1kcd5B6dlC05nq+k5GxQWYOa8rlCmqLHsUW9LCHABGFY+/srscEEywpFzC\nP7uimEwLsaKSkBPhJG5S0P4D3jDHBEuM8K7BXZXL7Y7hsozd1K/E2MBRrWhlsRZ/\ncgYS8S0zAgMBAAECggEALyun3wA0OoKzqP9HxGmmGCqnEr2pFCF4Fqum9aeu8a+7\nIZpCxKbPT1NUIYaf8Z050rrHjcgUM0IaObqAa+TTNn9qG7jvs+YDqYT670zc1ijZ\n8PvSLNROJF1mp55E3KvUu9wMarsrH5T21MjIMKrDMvScRtqyLEZSErJmiCmujlvt\nRJuUDzL3FFgax/RgS80FUWsmqGvBNL+guJfvYp4NwpSj+9xcV8Gaf8bI6CMIeWQd\nJ/vUGTT31yv2j5P5t1dnMfKdZSt2vFjdfizJKnhpj1sFgldwC+jSVzG9sRb1Xyb4\nZNWWJw27xZtp76xT92gIiU8AR+aO8wXdH5UcVmW56QKBgQD0h/lZttkNEoo4edV4\nelG3SMYEB/1fQ/ukG1EAVpOHfCpcuJEy0FOfsmQf5an4QF8L2EU50Td81HTnTJWK\nfLF9qAiIHa1mdUmtLjSelGgZOagG0BJhZeV6sdi+VayWhCbWmeEikS6zr+xwIv7S\nNuN83Gf3r9GMRvkbF8RI95Xc+wKBgQDXyDLWrWWdSjQEMa8D8U+eUzD6JrRlqa1z\nWptVcRXtQ+dvgPW36iz8lBo4DvTk1SsmEUeUO33YuO/timzCNqS9+2chtzSAJi3g\nJUpfIZoqwEbIpuJB5qr/rcUFHPtk4vGJeA7OLBJUsS3FLVoRCikf1jX9fHTLhzS3\nGSj/07YLKQKBgQCreH39zx488HdESwrKRNvwbnOMeB3QI9fdp9oRJqSlKQh7pGEN\nBNDe9zUGuQGLN3hu0eUZOgBy5HhliWqDhhTgTGhPKqBhbHWRnwj++opUxf1xaY66\nBb35X6ThMyqnEVw6uAULPEtHbWGa8K9HsX2sHNI6+WsztsEPoobds9++6QKBgQCQ\n2sFeIhsT4wtWQXAm6mizdU9srmztzmE1Df829Wpt0+bakKzjYN4AVP/g4BGASKXl\nsTXnCaTqxwOx5/ooynv/WXSbSpyA5qBnV0E86ZbP2jHqYzWCXfIvH50iWJle2Yah\n7SmrOCS6HBMIyfArfjGrQKcP2uug8cvumoJOcvZDOQKBgHoZhEHU/veIResRGF/y\nhPThSWJby8k4Rh7f//7SwZHAdG+zB2I81R92zOMhCwzdFIHQ2vattNpU/tW8dcHK\nXMZwbjhrGtF51NLkjHWTclP7KF2666gCGsFJ5qiJ9qxkgnAuqEwfSriU0xDMshxo\nsD808S+2pl4qks0EnHYC2uPi\n-----END PRIVATE KEY-----\n"
    fapi_ctx.import_object(path=key_path, import_data=key_private_pem)    
except Exception as e:
  print(e)
  pass

l = fapi_ctx.list(search_path="/HS/")
print(l)

digest = sha256(b"fff")

sig, pub,cert = fapi_ctx.sign(path=key_path, digest=digest, padding="rsa_ssa")
print(sig.hex())


fapi_ctx.verify_signature(path=key_path, digest=digest, signature=sig)



#fapi_ctx.delete("/")
fapi_ctx.close()




