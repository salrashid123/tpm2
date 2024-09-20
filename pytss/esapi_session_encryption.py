from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek

ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)

## use the ek rsa as the encryption basis
nv, tmpl = _ek.EK_RSA2048

inSensitive = TPM2B_SENSITIVE_CREATE()
handle, outpub, _, _, _ = ectx.create_primary(inSensitive,tmpl ,ESYS_TR.ENDORSEMENT)

n = ectx.tr_get_name(handle)

print(bytes(n).hex())
session = ectx.start_auth_session(
    tpm_key=handle,
    bind=ESYS_TR.NONE,
    session_type=TPM2_SE.POLICY,
    symmetric="aes128cfb",
    auth_hash="sha256",
)

ectx.trsess_set_attributes(
    session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
)

r = ectx.get_random( 8 , session1=session)
print(str(r))

ectx.flush_context(handle)

ectx.close()