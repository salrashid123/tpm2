from tpm2_pytss import *


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from tpm2_pytss.internal.templates import _ek


# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
# printf '\x00\x00' > /tmp/unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256 \
#     -c primary.ctx \
#     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
# tpm2_create -g sha256 -G aes128cfb -u key.pub -r key.prv -C primary.ctx 

# tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx  
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
# echo "foo" > secret.dat
# openssl rand  -out iv.bin 16

# tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c key.ctx -o encrypt.out secret.dat
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
# tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c key.ctx -d -o decrypt.out encrypt.out
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  


ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)


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

inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, _, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))


with open("/tmp/key.pub", "rb") as file:
    pu = file.read()

with open("/tmp/key.prv", "rb") as file:
    pr = file.read()

## if you want, you can write the pub/priv to disk (eg pub.marshal())
pub, _ = TPM2B_PUBLIC.unmarshal(pu)
priv, _ = TPM2B_PRIVATE.unmarshal(pr)

aesKeyHandle = ectx.load(primary1, priv,pub)
ectx.flush_context(primary1)


ivIn = TPM2B_IV(bytes(bytearray.fromhex("4ca91f6bc6376a33a4ddb8a9c3cf5ea9")))
inData = TPM2B_MAX_BUFFER(b"foo")

encrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData)
print(encrypted)

decrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrypted)
print(decrypted.marshal().decode("ascii"))

ectx.flush_context(aesKeyHandle)

ectx.close()

