from tpm2_pytss import *


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

inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(""))
    )
handle, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)


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