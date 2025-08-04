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

private_key_string="-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOHW00xKYNp0xv\ngbUDbedDyGDV6dM54TIBEiVZ0PPldACI6YBt8n+N5EnrrzkxEOEqTBQduhIQaGpe\nAgigU9MZPw1o1974Se7FIjRJA9nrvAkT2uEGAfq8wFgFnTvH7NbROGyaMEiwoAGI\nKAZfyXJ7Np095eLHSBx8xyP/j1OtrWw6M/duPR30X4bXdEZ8xbNbMsaz7+rYhuuU\n5XtUzJ1kcd5B6dlC05nq+k5GxQWYOa8rlCmqLHsUW9LCHABGFY+/srscEEywpFzC\nP7uimEwLsaKSkBPhJG5S0P4D3jDHBEuM8K7BXZXL7Y7hsozd1K/E2MBRrWhlsRZ/\ncgYS8S0zAgMBAAECggEALyun3wA0OoKzqP9HxGmmGCqnEr2pFCF4Fqum9aeu8a+7\nIZpCxKbPT1NUIYaf8Z050rrHjcgUM0IaObqAa+TTNn9qG7jvs+YDqYT670zc1ijZ\n8PvSLNROJF1mp55E3KvUu9wMarsrH5T21MjIMKrDMvScRtqyLEZSErJmiCmujlvt\nRJuUDzL3FFgax/RgS80FUWsmqGvBNL+guJfvYp4NwpSj+9xcV8Gaf8bI6CMIeWQd\nJ/vUGTT31yv2j5P5t1dnMfKdZSt2vFjdfizJKnhpj1sFgldwC+jSVzG9sRb1Xyb4\nZNWWJw27xZtp76xT92gIiU8AR+aO8wXdH5UcVmW56QKBgQD0h/lZttkNEoo4edV4\nelG3SMYEB/1fQ/ukG1EAVpOHfCpcuJEy0FOfsmQf5an4QF8L2EU50Td81HTnTJWK\nfLF9qAiIHa1mdUmtLjSelGgZOagG0BJhZeV6sdi+VayWhCbWmeEikS6zr+xwIv7S\nNuN83Gf3r9GMRvkbF8RI95Xc+wKBgQDXyDLWrWWdSjQEMa8D8U+eUzD6JrRlqa1z\nWptVcRXtQ+dvgPW36iz8lBo4DvTk1SsmEUeUO33YuO/timzCNqS9+2chtzSAJi3g\nJUpfIZoqwEbIpuJB5qr/rcUFHPtk4vGJeA7OLBJUsS3FLVoRCikf1jX9fHTLhzS3\nGSj/07YLKQKBgQCreH39zx488HdESwrKRNvwbnOMeB3QI9fdp9oRJqSlKQh7pGEN\nBNDe9zUGuQGLN3hu0eUZOgBy5HhliWqDhhTgTGhPKqBhbHWRnwj++opUxf1xaY66\nBb35X6ThMyqnEVw6uAULPEtHbWGa8K9HsX2sHNI6+WsztsEPoobds9++6QKBgQCQ\n2sFeIhsT4wtWQXAm6mizdU9srmztzmE1Df829Wpt0+bakKzjYN4AVP/g4BGASKXl\nsTXnCaTqxwOx5/ooynv/WXSbSpyA5qBnV0E86ZbP2jHqYzWCXfIvH50iWJle2Yah\n7SmrOCS6HBMIyfArfjGrQKcP2uug8cvumoJOcvZDOQKBgHoZhEHU/veIResRGF/y\nhPThSWJby8k4Rh7f//7SwZHAdG+zB2I81R92zOMhCwzdFIHQ2vattNpU/tW8dcHK\nXMZwbjhrGtF51NLkjHWTclP7KF2666gCGsFJ5qiJ9qxkgnAuqEwfSriU0xDMshxo\nsD808S+2pl4qks0EnHYC2uPi\n-----END PRIVATE KEY-----\n"

ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)


private_key = serialization.load_pem_private_key(
    private_key_string.encode('utf-8'),
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )



inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

public_key = private_key.public_key()
public_numbers = public_key.public_numbers()


modulus_n = public_numbers.n
n_bytes = modulus_n.to_bytes((modulus_n.bit_length() + 7) // 8, byteorder='big')

public  = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=TPMA_OBJECT.USERWITHAUTH 
                    | TPMA_OBJECT.SIGN_ENCRYPT,
            authPolicy=b"",
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    exponent=0, #public_numbers.e,
                    keyBits=2048,
                    symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
                    scheme=TPMT_RSA_SCHEME(
                        scheme=TPM2_ALG.RSASSA,
                        details=TPMU_ASYM_SCHEME(
                            TPMS_SCHEME_HASH(
                               hashAlg=TPM2_ALG.SHA256,
                           )
                        ),
                    ),                    
                ),
            ),
            unique=TPMU_PUBLIC_ID(
                rsa=n_bytes
            ),
        )
    )




sensitive = TPM2B_SENSITIVE.from_pem(pem_private_key)

symdef = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
symdef.mode.sym = TPM2_ALG.CFB
symdef.keyBits.sym = 128
enckey, duplicate, outsymseed = wrap(
        parent.publicArea, public, sensitive, b"", symdef
)
priv = ectx.import_(primary1, enckey, public, duplicate, outsymseed, symdef)

childHandle = ectx.load(primary1, priv, public)

ectx.flush_context(primary1)

scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)
    
# echo -n "fff" > /tmp/data.txt
## openssl dgst -sha256 -binary -out /tmp/data.sha256 /tmp/data.txt
## openssl pkeyutl -sign -in /tmp/data.sha256 -inkey ../example/certs/alice-cert.key  -out /tmp/signature.bin -pkeyopt rsa_padding_mode:pkcs1 -pkeyopt digest:sha256

s = ectx.sign(childHandle, TPM2B_DIGEST(digest), scheme, validation)

print("signature")
print(s.signature.rsassa.sig)

ectx.flush_context(childHandle)