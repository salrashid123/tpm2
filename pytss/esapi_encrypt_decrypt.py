from tpm2_pytss import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)

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

inPublicAES = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="aes",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.SIGN_ENCRYPT,
            )
)

inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicAES)
aesKeyHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)

ivIn = TPM2B_IV(b"thisis16bytes123")
inData = TPM2B_MAX_BUFFER(b"fooo")

encrpyted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData)

print(encrpyted.buffer.hex())
print(outIV2.buffer.hex())

decrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrpyted)

print(decrypted.marshal().decode("ascii"))

ectx.flush_context(aesKeyHandle)

