from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek
from tpm2_pytss.tsskey import TSSPrivKey

'''
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_create -g sha256 -G aes128cfb -u aes.pub -r aes.prv -C primary.ctx -p pass

tpm2_load -C primary.ctx -u aes.pub -r aes.prv -c aes.ctx  
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c aes.ctx -o encrypt.out secret.dat -p pass
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c aes.ctx -d -o decrypt.out encrypt.out  -p pass
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
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


ivIn = TPM2B_IV(b"thisis16bytes123")
inData = TPM2B_MAX_BUFFER(b"fooo")

ectx.tr_set_auth(aesKeyHandle, "pass")

encrypted, outIV2 = ectx.encrypt_decrypt_2(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData, session1=hsess)

print(encrypted.buffer.hex())
print(outIV2.buffer.hex())




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



decrypted, outIV2 = ectx.encrypt_decrypt_2(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrypted,  session1=hsess)

print(decrypted.marshal().decode("ascii"))

ectx.flush_context(handle)
ectx.flush_context(aesKeyHandle)


ectx.close()