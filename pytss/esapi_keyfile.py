from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey

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

_parent_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
            curveID=TPM2_ECC.NIST_P256,
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
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
primary1, _, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicAES)
k1= TSSPrivKey(priv,pub,empty_auth=True,parent=TPM2_RH.OWNER)



p1 = k1.to_pem()
f = open("/tmp/p1.pem", "w")
f.write(p1.decode())
f.close()


ectx.flush_context(primary1)



f = open("/tmp/p1.pem", "r")
k = TSSPrivKey.from_pem(f.read().encode("utf-8"))
aesKeyHandle = k.load(ectx,password='')

ivIn = TPM2B_IV(bytes(bytearray.fromhex("4ca91f6bc6376a33a4ddb8a9c3cf5ea9")))
inData = TPM2B_MAX_BUFFER(b"foo")

encrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData)
print(encrypted)

decrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrypted)
print(decrypted.marshal().decode("ascii"))

# see https://github.com/tpm2-software/tpm2-pytss/issues/595
ectx.flush_context(aesKeyHandle)

ectx.close()

