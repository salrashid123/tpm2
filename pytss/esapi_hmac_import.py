from tpm2_pytss import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)


# https://github.com/salrashid123/tpm2/tree/master/hmac_import
# echo -n "change this password to a secret" | xxd -p -c 100
#   6368616e676520746869732070617373776f726420746f206120736563726574
# echo -n foo > data.in
# openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
#        HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

k = 'change this password to a secret'

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

inPublicHMAC = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="hmac",
                nameAlg="sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.SIGN_ENCRYPT,
            )
)

inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)

inSensitiveHMAC = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE(data=TPM2B_SENSITIVE_DATA(k.encode("utf-8"))))
priv, pub, _, _, _ = ectx.create(primary1, inSensitiveHMAC, inPublicHMAC)



childHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)
thmac = ectx.hmac(childHandle, b"foo", TPM2_ALG.SHA256)
print(thmac)
print(thmac.__bytes__().hex())


ectx.flush_context(childHandle)