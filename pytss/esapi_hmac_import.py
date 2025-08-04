from tpm2_pytss import *
from tpm2_pytss.utils import *
from cryptography.hazmat.backends import default_backend


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


ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)


# https://github.com/salrashid123/tpm2/tree/master/hmac_import
# echo -n "change this password to a secret" | xxd -p -c 100
#   6368616e676520746869732070617373776f726420746f206120736563726574
# echo -n foo > data.in
# openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
#        HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

key = 'change this password to a secret'

inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

scheme = TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG.HMAC)
scheme.details.hmac.hashAlg = TPM2_ALG.SHA256
objectAttributes=TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT
    
sensitive, pu = TPM2B_SENSITIVE.keyedhash_from_secret(secret=key.encode("utf-8"),scheme=scheme,objectAttributes=objectAttributes)

symdef = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
symdef.mode.sym = TPM2_ALG.CFB
symdef.keyBits.sym = 128
enckey, duplicate, outsymseed = wrap(
        parent.publicArea, pu, sensitive, b"", symdef
)
priv = ectx.import_(primary1, enckey, pu, duplicate, outsymseed, symdef)

childHandle = ectx.load(primary1, priv, pu)
ectx.flush_context(primary1)
thmac = ectx.hmac(childHandle, b"foo", TPM2_ALG.SHA256)


print("hmac")
print(thmac)
ectx.flush_context(childHandle)
