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


# https://github.com/tpm2-software/tpm2-pytss/issues/504

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

inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(""))
    )

sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
)


primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)


session = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
)

# $ tpm2_pcrread sha256:23
#   sha256:
#     23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

pcrsels = TPML_PCR_SELECTION.parse("sha256:23")
_, _, digests, = ectx.pcr_read(pcrsels)
print(digests[0].hex())

def pcr_cb(selection):

            sel = TPMS_PCR_SELECTION(
                hash=TPM2_ALG.SHA256,
                sizeofSelect=selection.selections.pcr_select.sizeofSelect,
                pcrSelect=selection.selections.pcr_select.pcrSelect,
            )
            out_sel = TPML_PCR_SELECTION((sel,))
           
            digests = list()
            selb = bytes(sel.pcrSelect[0 : sel.sizeofSelect])
            seli = int.from_bytes(reversed(selb), "big")
            for i in range(0, sel.sizeofSelect * 8):
                if (1 << i) & seli:
                    dig = TPM2B_DIGEST(bytes([i]) * 32)
                    digests.append(dig)
            out_dig = TPML_DIGEST(digests)

            return (out_sel, out_dig)



ectx.policy_pcr(
    session, TPM2B_DIGEST(), TPML_PCR_SELECTION.parse("sha256:23")
)

policyDigest = ectx.policy_get_digest(session)
ectx.flush_context(session)

inPublicRSA.publicArea.authPolicy = policyDigest

priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicRSA)
childHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)

digest = sha256(b"fff")
scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)


session = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            auth_hash=TPM2_ALG.SHA256,
        )


pol={
    "description":"Policy PCR 23 TPM2_ALG_SHA256",
    "policy":[
        {
            "type":"POLICYPCR",
            "pcrs":[
                {
                    "pcr":23,
                    "hashAlg":"TPM2_ALG_SHA256",
                    "digest":"{}".format(digests[0].hex())
                }
            ]
        }
    ]
}


polstr = json.dumps(pol).encode()


# def pcr_cb(selection):

#             sel = TPMS_PCR_SELECTION(
#                 hash=TPM2_ALG.SHA256,
#                 sizeofSelect=selection.selections.pcr_select.sizeofSelect,
#                 pcrSelect=selection.selections.pcr_select.pcrSelect,
#             )
#             out_sel = TPML_PCR_SELECTION((sel,))
           
#             digests = list()
#             selb = bytes(sel.pcrSelect[0 : sel.sizeofSelect])
#             seli = int.from_bytes(reversed(selb), "big")
#             for i in range(0, sel.sizeofSelect * 8):
#                 if (1 << i) & seli:
#                     dig = TPM2B_DIGEST(bytes([i]) * 32)
#                     digests.append(dig)
#             out_dig = TPML_DIGEST(digests)

#             return (out_sel, out_dig)

try:
    with policy(polstr, TPM2_ALG.SHA256) as p:
                p.set_callback(policy_cb_types.CALC_PCR, pcr_cb)
                p.calculate()
                cjb = p.get_calculated_json()
                json_object = json.loads(cjb)
                print(json.dumps(json_object, indent=4))
                p.execute(ectx, session)
except Exception as e:
    print(e)
    sys.exit(1)

s = ectx.sign(childHandle, TPM2B_DIGEST(digest), scheme, validation, session1=session)

print(s.sigAlg)
print(s.signature.rsassa.hash)
print(s.signature.rsassa.sig)

ectx.flush_context(session)
ectx.flush_context(childHandle)

#ectx.verify_signature(childHandle,  TPM2B_DIGEST(digest), signature)

ectx.close()