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


f = open("rsa_auth_ek.pem", "r")
kb = f.read()
f.close()    
k = TSSPrivKey.from_pem(kb.encode('utf-8'))
pub = k.public
priv = k.private


tmpl = ek_rsa2048.template

inSensitive = TPM2B_SENSITIVE_CREATE()


inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, outpub, _, _, _ = ectx.create_primary(
    inSensitive, tmpl, ESYS_TR.ENDORSEMENT)


def setup_ek_session(ectx):
                    sym = TPMT_SYM_DEF(
                        algorithm=TPM2_ALG.XOR,
                        keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
                        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
                    )
                    session = ectx.start_auth_session(
                        tpm_key=ESYS_TR.NONE,
                        bind=ESYS_TR.NONE,
                        session_type=TPM2_SE.POLICY,
                        symmetric=sym,
                        auth_hash=TPM2_ALG.SHA256,
                    )
                    nonce = ectx.trsess_get_nonce_tpm(session)
                    expiration = -(10 * 365 * 24 * 60 * 60)
                    ectx.policy_secret(
                        ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration
                    )
                    ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
                    return session


sess = setup_ek_session(ectx)
rkeyLoaded = ectx.load(primary1, k.private, k.public,  session1=sess)
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

print(s.sigAlg)
print(s.signature.rsassa.hash)
print(s.signature.rsassa.sig)


ectx.verify_signature(rkeyLoaded,  TPM2B_DIGEST(digest), s)
ectx.flush_context(handle)
ectx.flush_context(rkeyLoaded)


ectx.close()
