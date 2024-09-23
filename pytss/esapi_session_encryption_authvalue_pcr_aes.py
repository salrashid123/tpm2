from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek
from tpm2_pytss.tsskey import TSSPrivKey


'''
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_startauthsession -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext session.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_create -g sha256 -G aes128cfb -u aes.pub -r aes.prv -C primary.ctx -L policy.dat -p pass 
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_load -C primary.ctx -u aes.pub -r aes.prv -n aes.name -c aes.ctx  

echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat

tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out   secret.dat  -p"session:session.dat+pass"
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

## redo the policy again 
tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat

tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p"session:session.dat+pass"
'''


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


with open("/tmp/aes.pub", "rb") as file:
    pu = file.read()

with open("/tmp/aes.prv", "rb") as file:
    pr = file.read()

## if you want, you can write the pub/priv to disk (eg pub.marshal())
pub, _ = TPM2B_PUBLIC.unmarshal(pu)
priv, _ = TPM2B_PRIVATE.unmarshal(pr)

aesKeyHandle = ectx.load(primary1, priv,pub)
ectx.flush_context(primary1)


nv, tmpl = _ek.EK_RSA2048

inSensitive = TPM2B_SENSITIVE_CREATE()
handle, outpub, _, _, _ = ectx.create_primary(
    inSensitive, tmpl, ESYS_TR.ENDORSEMENT)

ivIn = TPM2B_IV(b"thisis16bytes123")
inData = TPM2B_MAX_BUFFER(b"fooo")

ectx.tr_set_auth(aesKeyHandle, "pass")

pcrsels = TPML_PCR_SELECTION.parse("sha256:23")
_, _, digests, = ectx.pcr_read(pcrsels)
print(digests[0].hex())

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

sess = ectx.start_auth_session(
            tpm_key=handle,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(sym=128),
                mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            ),        
            auth_hash=TPM2_ALG.SHA256,
        )

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

try:
    with policy(polstr, TPM2_ALG.SHA256) as p:
                p.set_callback(policy_cb_types.CALC_PCR, pcr_cb)
                p.calculate()
                cjb = p.get_calculated_json()
                json_object = json.loads(cjb)
                print(json.dumps(json_object, indent=4))
                p.execute(ectx, sess)
except Exception as e:
    print(e)
    sys.exit(1)


ectx.policy_auth_value(sess)
  
ectx.trsess_set_attributes(
    sess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT )
)     
            


encrypted, outIV2 = ectx.encrypt_decrypt_2(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData,  session1=sess)

print(encrypted.buffer.hex())
print(outIV2.buffer.hex())

ectx.flush_context(handle)
ectx.flush_context(aesKeyHandle)


ectx.close()