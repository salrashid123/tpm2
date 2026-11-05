from tpm2_pytss import *
from tpm2_pytss.internal.templates import ek_rsa2048
from tpm2_pytss.tsskey import TSSPrivKey

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend



def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


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

f = open("rsa_auth_h2.pem", "r")

kb = f.read()
f.close()    
k = TSSPrivKey.from_pem(kb.encode('utf-8'))
pub = k.public
priv = k.private


rkeyLoaded = ectx.load(primary1, k.private, k.public)
ectx.flush_context(primary1)

scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)


tmpl = ek_rsa2048.template
inSensitive = TPM2B_SENSITIVE_CREATE()
handle, outpub, _, _, _ = ectx.create_primary(
    inSensitive, tmpl, ESYS_TR.ENDORSEMENT)

hsess = ectx.start_auth_session(
    tpm_key=handle,
    bind=ESYS_TR.NONE,
    session_type=TPM2_SE.HMAC,
    symmetric=TPMT_SYM_DEF(
        algorithm=TPM2_ALG.AES,
        keyBits=TPMU_SYM_KEY_BITS(sym=128),
        mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
    ),
    auth_hash=TPM2_ALG.SHA256,
)
ectx.trsess_set_attributes(
    hsess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT )
)         

s = ectx.sign(rkeyLoaded,  TPM2B_DIGEST(digest), scheme, validation, session1=hsess)
ectx.flush_context(handle)
print(s.sigAlg)
print(s.signature.rsassa.hash)
print(s.signature.rsassa.sig)


ectx.verify_signature(rkeyLoaded,  TPM2B_DIGEST(digest), s)

ectx.flush_context(rkeyLoaded)

ectx.close()
