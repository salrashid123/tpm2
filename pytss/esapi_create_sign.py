from tpm2_pytss import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest

ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)
r = ectx.get_random( 8 )
print(str(r))


inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
)

inPublicRSA = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048:rsassa:null",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
                | TPMA_OBJECT.SIGN_ENCRYPT,
            )
)

inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicRSA)
childHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)

digest = sha256(b"fff")
scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)

signature = ectx.sign(childHandle, TPM2B_DIGEST(digest), scheme, validation)
print(signature.marshal().hex())

ectx.verify_signature(childHandle,  TPM2B_DIGEST(digest), signature)
ectx.flush_context(childHandle)

ectx.close()