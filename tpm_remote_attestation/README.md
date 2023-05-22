
see 

- [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)


using my raspberry pi which does _not_ have an eventlog

## on Raspberry PI

```bash
go run src/grpc_attestor.go --grpcport :50051 \
 --unsealPcrs=23 \
 --caCertTLS certs/CA_crt.pem \
 --servercert certs/attestor_crt.pem \
 --serverkey certs/attestor_key.pem \
  -useFullAttestation --readEventLog=false \
  --platformCertFile certs/platform_cert.der \
  --v=10 -alsologtostderr
```

note, `--readEventLog=false` as i dont' have an eventlog on the pi

aslo assume tpm pcr 0, 23 is
```bash
tpm2_pcrread  sha1:0+sha256:23
  sha1:
    0 : 0x0000000000000000000000000000000000000000
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
```


## on local


note


```bash
go run src/grpc_verifier.go --importMode=AES  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 --readEventLog \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
   --host 108.56.239.251:50051 \
   --expectedPCRMapSHA256 23:0000000000000000000000000000000000000000000000000000000000000000 \
   --expectedPCRMapSHA1 0:0000000000000000000000000000000000000000 \
   --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem --platformCA certs/CA_crt.pem \
   --readEventLog=false \
   --v=10 -alsologtostderr 
```

in the logs below, note that we're talking with a 'real' tpm (note i dont' have eventlog/secure boot checks on)

```log
I0521 11:22:57.836198   51396 grpc_verifier.go:237] =============== GetEKCert Returned from remote ===============
I0521 11:22:57.836332   51396 grpc_verifier.go:257]      EKCert Encryption Issuer x509 

CN=Infineon OPTIGA(TM) TPM 2.0 RSA CA 041,OU=OPTIGA(TM),O=Infineon Technologies AG,C=DE  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

I0521 11:22:57.836390   51396 grpc_verifier.go:258]      EKCert Encryption SerialNumber 
145633230

I0521 11:22:57.836410   51396 grpc_verifier.go:260]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AGTl6+cUrY3gGV4ou/b
tsHYIhfPYtBHxofy8jgIY1R/MMBI36CLbx3oxGwQYcRnOJ//n0jd6JKHunhC9xH+
ERXll8lKaNg+aY+VjXGQuRgySlh4DGR7nAHe0VhU5iD/gBgExEAJiP/gzrvPtZJm
GmeBq+YqQtDBgEOanV0T0hfcXzljRtptQ24laDmpwxzIMsHtPCYADMzkbWjKRuWr
4+h5PwpQmmf29qcB4yhr5nmD8hDaPf9jysbP3ti7xpRO2LhV+Uuhyd2uBEyn+T3t
9+i8GI9ONsu5Sb3iIPQ20sYh9nKihsUq3x8Xb7cJE8qTBpvPmv9L6TZ5y3csiKey
AwIDAQAB
-----END PUBLIC KEY-----

I0521 11:22:57.845549   51396 grpc_verifier.go:273]      Read (eK) from request with name: 000b685ffa7d67b7cae1d0cc6697b4aa6f574400e8575e7d0a56b25b0899912c0f10
I0521 11:22:57.845586   51396 grpc_verifier.go:276]      EK Default parameter match template
```

---


#### TPM

- `attestor`

```log
go run src/grpc_attestor.go --grpcport :50051 \
  --unsealPcrs=23 \
  --caCertTLS certs/CA_crt.pem \
  --servercert certs/attestor_crt.pem \
  --serverkey certs/attestor_key.pem \
   -useFullAttestation --readEventLog=false \
   --platformCertFile certs/platform_cert.der \
   --v=10 -alsologtostderr

I0521 11:22:55.719621    8530 grpc_attestor.go:1364] Starting gRPC server on port :50051
I0521 11:22:57.743900    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:57.744030    8530 grpc_attestor.go:156] HealthCheck called for Service [verifier.VerifierServer]
I0521 11:22:57.752019    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:57.752161    8530 grpc_attestor.go:170] ======= GetPlatformCert ========
I0521 11:22:57.752238    8530 grpc_attestor.go:171]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:57.752607    8530 grpc_attestor.go:189]      Returning GetPlatformCert ========
I0521 11:22:57.758738    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:57.759505    8530 grpc_attestor.go:288] ======= GetEKCert ========
I0521 11:22:57.760080    8530 grpc_attestor.go:289]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:57.760636    8530 grpc_attestor.go:295] =============== Load EncryptionKey and Certifcate from NV ===============
I0521 11:22:57.778972    8530 grpc_attestor.go:314]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AGTl6+cUrY3gGV4ou/b
tsHYIhfPYtBHxofy8jgIY1R/MMBI36CLbx3oxGwQYcRnOJ//n0jd6JKHunhC9xH+
ERXll8lKaNg+aY+VjXGQuRgySlh4DGR7nAHe0VhU5iD/gBgExEAJiP/gzrvPtZJm
GmeBq+YqQtDBgEOanV0T0hfcXzljRtptQ24laDmpwxzIMsHtPCYADMzkbWjKRuWr
4+h5PwpQmmf29qcB4yhr5nmD8hDaPf9jysbP3ti7xpRO2LhV+Uuhyd2uBEyn+T3t
9+i8GI9ONsu5Sb3iIPQ20sYh9nKihsUq3x8Xb7cJE8qTBpvPmv9L6TZ5y3csiKey
AwIDAQAB
-----END PUBLIC KEY-----
I0521 11:22:57.820904    8530 grpc_attestor.go:343]      Encryption Issuer x509 Infineon OPTIGA(TM) TPM 2.0 RSA CA 041
I0521 11:22:57.822011    8530 grpc_attestor.go:345]      Returning GetEKCert
I0521 11:22:57.849677    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:57.850605    8530 grpc_attestor.go:354] ======= GetAK ========
I0521 11:22:57.851272    8530 grpc_attestor.go:355]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:57.858770    8530 grpc_attestor.go:363]      PCR [23] Value 0000000000000000000000000000000000000000000000000000000000000000 
I0521 11:22:57.859708    8530 grpc_attestor.go:369]      createPrimary
I0521 11:22:57.917670    8530 grpc_attestor.go:393]      tpmEkPub: 
&{26258344850482389995546679172575636402193028340520893155145236190500463014824865479293565484614784202502524006732513713124645735078275222022457884968518805107326288342532662422964585429640711965550033187266222025106831505030854385176555233600566379437531904132578368808622946244500365740299315181875719150164848065165183667412410331662072320320629064063629823328709988055152624021769547469270163850177507599551730998728782183708686007017082227488261094874575127666139779770260660891500341647964363815523537990482511241166752623861605975930181662598934683897117411649300113664026950039122189350992277206109673058972163 65537}
I0521 11:22:57.919936    8530 grpc_attestor.go:406]      ekPub Name: 000b685ffa7d67b7cae1d0cc6697b4aa6f574400e8575e7d0a56b25b0899912c0f10
I0521 11:22:57.920965    8530 grpc_attestor.go:407]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AGTl6+cUrY3gGV4ou/b
tsHYIhfPYtBHxofy8jgIY1R/MMBI36CLbx3oxGwQYcRnOJ//n0jd6JKHunhC9xH+
ERXll8lKaNg+aY+VjXGQuRgySlh4DGR7nAHe0VhU5iD/gBgExEAJiP/gzrvPtZJm
GmeBq+YqQtDBgEOanV0T0hfcXzljRtptQ24laDmpwxzIMsHtPCYADMzkbWjKRuWr
4+h5PwpQmmf29qcB4yhr5nmD8hDaPf9jysbP3ti7xpRO2LhV+Uuhyd2uBEyn+T3t
9+i8GI9ONsu5Sb3iIPQ20sYh9nKihsUq3x8Xb7cJE8qTBpvPmv9L6TZ5y3csiKey
AwIDAQAB
-----END PUBLIC KEY-----
I0521 11:22:57.926912    8530 grpc_attestor.go:421]      CreateKeyUsingAuth
I0521 11:22:58.471471    8530 grpc_attestor.go:472]      ContextSave (ek)
I0521 11:22:58.511522    8530 grpc_attestor.go:485]      ContextLoad (ek)
I0521 11:22:58.544856    8530 grpc_attestor.go:498]      LoadUsingAuth
I0521 11:22:58.592186    8530 grpc_attestor.go:535]      AK keyName 0022000bc9edb050142e3fa7ea11f51bfcaf8daf4e0764e634eb4ae1d9dab27b3eb66208
I0521 11:22:58.598772    8530 grpc_attestor.go:560]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmXsFwbMCnsVcowOkc54g
lPMKo747b/+w5eplGVF5JKIl5i2pCXvJCp0RHb/T2nMnQO7LFle4ukVGQy2obIZd
dFdjkKzn8rprqc0JRxLG+c3C0yDBEZhEKQ8CPqK3hVGe773BNekNlHugXQ9/XYJR
bKDv1TkUT0QfoYrkl50iZvbDu4ltGufLg6VIUIUrw84EefUzh2RI89a4duBJJZzp
Z6XJ/woBH/x7OuUT6ZnoUdFCVLClALfsMDZtQ/4SNLOXUWAnzlCfXbis8OtMYbPx
HrPVNTiYWAaFJ/LIUmctqt1UwxJ6iEeNQ1rtQt3gxFrE35UGX0wCe+WY1qZXnHhE
CQIDAQAB
-----END PUBLIC KEY-----
I0521 11:22:58.599148    8530 grpc_attestor.go:562]      Write (akPub) ========
I0521 11:22:58.600221    8530 grpc_attestor.go:568]      Write (akPriv) ========
I0521 11:22:58.601125    8530 grpc_attestor.go:580]      Returning GetAK ========
I0521 11:22:58.659741    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:58.659858    8530 grpc_attestor.go:592] ======= ActivateCredential ========
I0521 11:22:58.659929    8530 grpc_attestor.go:593]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:58.660003    8530 grpc_attestor.go:595]      ContextLoad (ek)
I0521 11:22:58.691953    8530 grpc_attestor.go:608]      Read (akPub)
I0521 11:22:58.692306    8530 grpc_attestor.go:614]      Read (akPriv)
I0521 11:22:58.734143    8530 grpc_attestor.go:656]      keyName 0022000bc9edb050142e3fa7ea11f51bfcaf8daf4e0764e634eb4ae1d9dab27b3eb66208
I0521 11:22:58.734356    8530 grpc_attestor.go:658]      ActivateCredentialUsingAuth
I0521 11:22:58.984795    8530 grpc_attestor.go:711]      <--  activateCredential()
I0521 11:22:59.010354    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:59.011265    8530 grpc_attestor.go:721] ======= Quote ========
I0521 11:22:59.011913    8530 grpc_attestor.go:722]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:59.018120    8530 grpc_attestor.go:730]      PCR [23] Value 0000000000000000000000000000000000000000000000000000000000000000 
I0521 11:22:59.018255    8530 grpc_attestor.go:736]      ContextLoad (ek) ========
I0521 11:22:59.049870    8530 grpc_attestor.go:748]      LoadUsingAuth ========
I0521 11:22:59.060741    8530 grpc_attestor.go:772]      Read (akPub) ========
I0521 11:22:59.061042    8530 grpc_attestor.go:778]      Read (akPriv) ========
I0521 11:22:59.088554    8530 grpc_attestor.go:792]      AK keyName 0022000bc9edb050142e3fa7ea11f51bfcaf8daf4e0764e634eb4ae1d9dab27b3eb66208
I0521 11:22:59.278940    8530 grpc_attestor.go:811]      <-- End Quote
I0521 11:22:59.358261    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:59.358457    8530 grpc_attestor.go:823] ======= PushSecret ========
I0521 11:22:59.358569    8530 grpc_attestor.go:824]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:59.358727    8530 grpc_attestor.go:827]      Loading EndorsementKeyRSA
I0521 11:22:59.372001    8530 grpc_attestor.go:844]      Importing External Key
I0521 11:22:59.696473    8530 grpc_attestor.go:850]      <-- End importKey()
I0521 11:22:59.696716    8530 grpc_attestor.go:854]      Hash of imported Key bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU=
I0521 11:22:59.760877    8530 grpc_attestor.go:133] >> inbound request
I0521 11:22:59.761000    8530 grpc_attestor.go:943] ======= PullRSAKey ========
I0521 11:22:59.761074    8530 grpc_attestor.go:944]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:59.761151    8530 grpc_attestor.go:946] ======= Generate UnrestrictedKey ========
I0521 11:22:59.761222    8530 grpc_attestor.go:948]      ContextLoad (ek) ========
I0521 11:22:59.793078    8530 grpc_attestor.go:961]      Loading AttestationKey
I0521 11:22:59.831493    8530 grpc_attestor.go:1002]      AK keyName: ACIAC8ntsFAULj+n6hH1G/yvja9OB2TmNOtK4dnasns+tmII,
I0521 11:22:59.835369    8530 grpc_attestor.go:1029]      akPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmXsFwbMCnsVcowOkc54g
lPMKo747b/+w5eplGVF5JKIl5i2pCXvJCp0RHb/T2nMnQO7LFle4ukVGQy2obIZd
dFdjkKzn8rprqc0JRxLG+c3C0yDBEZhEKQ8CPqK3hVGe773BNekNlHugXQ9/XYJR
bKDv1TkUT0QfoYrkl50iZvbDu4ltGufLg6VIUIUrw84EefUzh2RI89a4duBJJZzp
Z6XJ/woBH/x7OuUT6ZnoUdFCVLClALfsMDZtQ/4SNLOXUWAnzlCfXbis8OtMYbPx
HrPVNTiYWAaFJ/LIUmctqt1UwxJ6iEeNQ1rtQt3gxFrE35UGX0wCe+WY1qZXnHhE
CQIDAQAB
-----END PUBLIC KEY-----
I0521 11:22:59.835663    8530 grpc_attestor.go:1033]      ======= CreateKeyUsingAuthUnrestricted ========
I0521 11:22:59.851439    8530 grpc_attestor.go:1066]      PCR [23] Value 0000000000000000000000000000000000000000000000000000000000000000 
I0521 11:23:00.371909    8530 grpc_attestor.go:1084]      Write (ukPub) ========
I0521 11:23:00.373000    8530 grpc_attestor.go:1090]      Write (ukPriv) ========
I0521 11:23:00.415382    8530 grpc_attestor.go:1153]      uakPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvE42BY3yu/ogci+1PIAG
4P39tkIyOGInFOMKJ680Csth/bcB/UXfXRq4OPVudWukwy1GwYLx2IM/l5F3BQW9
zbloW69S504l4KoRJ5OxV+Ztf91JfRo8UkffNPvpyXgJU1ZFBrqs5XVRno8LFCEU
yi89MBb6DaCbEgE2/qcf4zHs4BNle0VREz+Ag7Ph8MAhNfrethbSDt1T8X+N/aeg
A/+Gd48Hzw00E/uV1ypGryrd8kUumrgt4zbt5OiRDoSsUirQQwnQP55DOus7eBME
3vjXXmMY0bth8PaJERmABwEbcCtG1AK83z8XTytNu+9xOFW3seLth1BVMKQh4vPe
lwIDAQAB
-----END PUBLIC KEY-----
I0521 11:23:00.609671    8530 grpc_attestor.go:1169]      Data to sign: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:23:00.820709    8530 grpc_attestor.go:1185]      Test Signature:  hLZQPjLCzWBXlhDSraZQSz3TjBBl52OykCRnCSR3oj2Q22l6F9TD8ajvkZcfRrcTBhPisPSfRPx9M31LfbxwXlfjlVChwkncPjtH7fVwWtnH4fhBRY9AUkRsUzwflm4n3YZ9KGIG++BZRGhIBaCdA/+mIVwKPjM6ri2isxHuOGw34XoHMI195iCplU6LX4Cas3P1T3XRkwILsckSJKUXVooh37fQ3VhgT1hdxeDQDoIGaWH/qlkqfFvg5SpqH9vvKI6cC3WnwiVLecG+Ja2xRFwR3Kb33zVR20oKTgt0RXMITDEWAP/CcYjIlFR5rpnZ9frkfUdw8+UIDwfU+6jc2g
I0521 11:23:00.821462    8530 grpc_attestor.go:1237]      Decoding PublicKey for AK ========
I0521 11:23:00.825371    8530 grpc_attestor.go:1266]      Signature Verified
I0521 11:23:00.825766    8530 grpc_attestor.go:1281]      Returning PullRSAKeyResponse
```

- `verifier`

```log
go run src/grpc_verifier.go --importMode=AES  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 --readEventLog \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
   --host 108.56.239.251:50051 \
   --expectedPCRMapSHA256 23:0000000000000000000000000000000000000000000000000000000000000000 \
   --expectedPCRMapSHA1 0:0000000000000000000000000000000000000000 \
   --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem --platformCA certs/CA_crt.pem \
   --readEventLog=false \
   --v=10 -alsologtostderr 

I0521 11:22:57.749520   51396 grpc_verifier.go:169] RPC HealthChekStatus:SERVING
I0521 11:22:57.750217   51396 grpc_verifier.go:173] =============== GetPlatformCert ===============
I0521 11:22:57.756280   51396 grpc_verifier.go:182] =============== GetPlatformCert Returned from remote ===============
I0521 11:22:57.756326   51396 grpc_verifier.go:183]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:22:57.757268   51396 grpc_verifier.go:214]  Verified Platform cert signed by privacyCA
I0521 11:22:57.757316   51396 grpc_verifier.go:219]  Platform Cert's Holder SerialNumber 1b001fe40bf96774751a72e9f5de5333d6b62
I0521 11:22:57.836198   51396 grpc_verifier.go:237] =============== GetEKCert Returned from remote ===============
I0521 11:22:57.836332   51396 grpc_verifier.go:257]      EKCert Encryption Issuer x509 
CN=Infineon OPTIGA(TM) TPM 2.0 RSA CA 041,OU=OPTIGA(TM),O=Infineon Technologies AG,C=DE
I0521 11:22:57.836390   51396 grpc_verifier.go:258]      EKCert Encryption SerialNumber 
145633230
I0521 11:22:57.836410   51396 grpc_verifier.go:260]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AGTl6+cUrY3gGV4ou/b
tsHYIhfPYtBHxofy8jgIY1R/MMBI36CLbx3oxGwQYcRnOJ//n0jd6JKHunhC9xH+
ERXll8lKaNg+aY+VjXGQuRgySlh4DGR7nAHe0VhU5iD/gBgExEAJiP/gzrvPtZJm
GmeBq+YqQtDBgEOanV0T0hfcXzljRtptQ24laDmpwxzIMsHtPCYADMzkbWjKRuWr
4+h5PwpQmmf29qcB4yhr5nmD8hDaPf9jysbP3ti7xpRO2LhV+Uuhyd2uBEyn+T3t
9+i8GI9ONsu5Sb3iIPQ20sYh9nKihsUq3x8Xb7cJE8qTBpvPmv9L6TZ5y3csiKey
AwIDAQAB
-----END PUBLIC KEY-----

I0521 11:22:57.845549   51396 grpc_verifier.go:273]      Read (eK) from request with name: 000b685ffa7d67b7cae1d0cc6697b4aa6f574400e8575e7d0a56b25b0899912c0f10
I0521 11:22:57.845586   51396 grpc_verifier.go:276]      EK Default parameter match template
I0521 11:22:57.845596   51396 grpc_verifier.go:283] =============== GetAKCert ===============
I0521 11:22:58.622390   51396 grpc_verifier.go:295] =============== MakeCredential ===============
I0521 11:22:58.622498   51396 grpc_verifier.go:317]      Decoded EkPublic Key: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0AGTl6+cUrY3gGV4ou/b
tsHYIhfPYtBHxofy8jgIY1R/MMBI36CLbx3oxGwQYcRnOJ//n0jd6JKHunhC9xH+
ERXll8lKaNg+aY+VjXGQuRgySlh4DGR7nAHe0VhU5iD/gBgExEAJiP/gzrvPtZJm
GmeBq+YqQtDBgEOanV0T0hfcXzljRtptQ24laDmpwxzIMsHtPCYADMzkbWjKRuWr
4+h5PwpQmmf29qcB4yhr5nmD8hDaPf9jysbP3ti7xpRO2LhV+Uuhyd2uBEyn+T3t
9+i8GI9ONsu5Sb3iIPQ20sYh9nKihsUq3x8Xb7cJE8qTBpvPmv9L6TZ5y3csiKey
AwIDAQAB
-----END PUBLIC KEY-----
I0521 11:22:58.631764   51396 grpc_verifier.go:345]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmXsFwbMCnsVcowOkc54g
lPMKo747b/+w5eplGVF5JKIl5i2pCXvJCp0RHb/T2nMnQO7LFle4ukVGQy2obIZd
dFdjkKzn8rprqc0JRxLG+c3C0yDBEZhEKQ8CPqK3hVGe773BNekNlHugXQ9/XYJR
bKDv1TkUT0QfoYrkl50iZvbDu4ltGufLg6VIUIUrw84EefUzh2RI89a4duBJJZzp
Z6XJ/woBH/x7OuUT6ZnoUdFCVLClALfsMDZtQ/4SNLOXUWAnzlCfXbis8OtMYbPx
HrPVNTiYWAaFJ/LIUmctqt1UwxJ6iEeNQ1rtQt3gxFrE35UGX0wCe+WY1qZXnHhE
CQIDAQAB
-----END PUBLIC KEY-----
I0521 11:22:58.631820   51396 grpc_verifier.go:348]      AK Default parameter match template
I0521 11:22:58.640610   51396 grpc_verifier.go:357]      Loaded AK KeyName 000bc9edb050142e3fa7ea11f51bfcaf8daf4e0764e634eb4ae1d9dab27b3eb66208
I0521 11:22:58.640664   51396 grpc_verifier.go:359]      MakeCredential Start
I0521 11:22:58.640696   51396 grpc_verifier.go:365]      Sending Nonce: DGImmgcFrrxVaduLspmhiXrIgJDVaiFB
I0521 11:22:58.658215   51396 grpc_verifier.go:370]      <-- End makeCredential()
I0521 11:22:58.658261   51396 grpc_verifier.go:375] =============== ActivateCredential ===============
I0521 11:22:59.008145   51396 grpc_verifier.go:386]      Returned Secret: DGImmgcFrrxVaduLspmhiXrIgJDVaiFB
I0521 11:22:59.008241   51396 grpc_verifier.go:392]      AK Verification Complete
I0521 11:22:59.008311   51396 grpc_verifier.go:398]      Sending Quote with Nonce: UwHwbgVfnompvrbVpgefaOuzIJOONPnC
I0521 11:22:59.008389   51396 grpc_verifier.go:450] =============== Quote/Verify ===============
I0521 11:22:59.349988   51396 grpc_verifier.go:472]      Attestation ExtraData (nonce): UwHwbgVfnompvrbVpgefaOuzIJOONPnC 
I0521 11:22:59.350100   51396 grpc_verifier.go:473]      Attestation PCR#: [23] 
I0521 11:22:59.350207   51396 grpc_verifier.go:474]      Attestation Hash: 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925 
I0521 11:22:59.350304   51396 grpc_verifier.go:489]      sha256 of Expected PCR Value: --> 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
I0521 11:22:59.350400   51396 grpc_verifier.go:495]      Decoding PublicKey for AK ========
I0521 11:22:59.350755   51396 grpc_verifier.go:509]      Quote/Verify nonce Verified 
I0521 11:22:59.350849   51396 grpc_verifier.go:543]      <-- End verifyQuote()
I0521 11:22:59.350940   51396 grpc_verifier.go:545] =============== PushSecret ===============
I0521 11:22:59.351030   51396 grpc_verifier.go:551]      Generate Test Certificate for AK 
I0521 11:22:59.351137   51396 grpc_verifier.go:563]      Issuing certificate with serialNumber 383820
I0521 11:22:59.356225   51396 grpc_verifier.go:621]      X509 issued by Verifier for Ak: 
-----BEGIN CERTIFICATE-----
MIID0DCCArigAwIBAgIDBdtMMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAlVT
MQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJpc2UxIjAgBgNVBAMM
GUVudGVycHJpc2UgU3Vib3JkaW5hdGUgQ0EwHhcNMjMwNTIxMTUyMjU5WhcNMjMw
NTIyMTUyMjU5WjCBgjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzARBgNV
BAsTCkVudGVycHJpc2UxHzAdBgNVBAMTFnZlcmlmeS5lc29kZW1vYXBwMi5jb20w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZewXBswKexVyjA6RzniCU
8wqjvjtv/7Dl6mUZUXkkoiXmLakJe8kKnREdv9PacydA7ssWV7i6RUZDLahshl10
V2OQrOfyumupzQlHEsb5zcLTIMERmEQpDwI+oreFUZ7vvcE16Q2Ue6BdD39dglFs
oO/VORRPRB+hiuSXnSJm9sO7iW0a58uDpUhQhSvDzgR59TOHZEjz1rh24EklnOln
pcn/CgEf/Hs65RPpmehR0UJUsKUAt+wwNm1D/hI0s5dRYCfOUJ9duKzw60xhs/Ee
s9U1OJhYBoUn8shSZy2q3VTDEnqIR41DWu1C3eDEWsTflQZfTAJ75ZjWpleceEQJ
AgMBAAGjeTB3MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFLe6sAKh5740xsEFXGZ45btTXaFUMCEG
A1UdEQQaMBiCFnZlcmlmeS5lc29kZW1vYXBwMi5jb20wDQYJKoZIhvcNAQELBQAD
ggEBAHlQIPsoy8AzlLVKsYcmLIEHIMcr+MXHUpqxbZGLm6buh9LhibQzEi6DBXO0
hm3oSU9eZUKkjByFFaJzChbj+pR9ZofOaTgcIIIAGHLkBPCuEu3vgtvLpGC5gmCg
jyKSNxXrERq9THi/Yt0PD0GY5yOiXpIZipA8B8sV3vOaNCVKo5vaKdCdVXOrpYPI
0JyrTx5voyQijUFaX+VxYMKUlJeMT8EqZOZLbpaNK5LhXnCYQrc1LeVmVLqVIfRd
1iguWWv1cWBo7eXVF33B5C1BJQAK8kR8OfOLJQSKj1DpdpA33rPnHb0A41I+icSz
3W3V3dfcf3ImPyM9xXewJ8pJ23M=
-----END CERTIFICATE-----
I0521 11:22:59.356277   51396 grpc_verifier.go:623]      Pushing AES
I0521 11:22:59.356561   51396 grpc_verifier.go:652]      Hash of AES Key:  bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU
I0521 11:22:59.759718   51396 grpc_verifier.go:720]      Verification bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU
I0521 11:22:59.759874   51396 grpc_verifier.go:725] =============== PullRSAKey ===============
I0521 11:23:00.892628   51396 grpc_verifier.go:755]      Attestation of Unrestricted Signing Key Verified
I0521 11:23:00.892881   51396 grpc_verifier.go:773]      Unrestricted key parameter matches template
I0521 11:23:00.893132   51396 grpc_verifier.go:790]      uakPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvE42BY3yu/ogci+1PIAG
4P39tkIyOGInFOMKJ680Csth/bcB/UXfXRq4OPVudWukwy1GwYLx2IM/l5F3BQW9
zbloW69S504l4KoRJ5OxV+Ztf91JfRo8UkffNPvpyXgJU1ZFBrqs5XVRno8LFCEU
yi89MBb6DaCbEgE2/qcf4zHs4BNle0VREz+Ag7Ph8MAhNfrethbSDt1T8X+N/aeg
A/+Gd48Hzw00E/uV1ypGryrd8kUumrgt4zbt5OiRDoSsUirQQwnQP55DOus7eBME
3vjXXmMY0bth8PaJERmABwEbcCtG1AK83z8XTytNu+9xOFW3seLth1BVMKQh4vPe
lwIDAQAB
-----END PUBLIC KEY-----
I0521 11:23:00.893303   51396 grpc_verifier.go:795]      SigningKey Test Signature hLZQPjLCzWBXlhDSraZQSz3TjBBl52OykCRnCSR3oj2Q22l6F9TD8ajvkZcfRrcTBhPisPSfRPx9M31LfbxwXlfjlVChwkncPjtH7fVwWtnH4fhBRY9AUkRsUzwflm4n3YZ9KGIG++BZRGhIBaCdA/+mIVwKPjM6ri2isxHuOGw34XoHMI195iCplU6LX4Cas3P1T3XRkwILsckSJKUXVooh37fQ3VhgT1hdxeDQDoIGaWH/qlkqfFvg5SpqH9vvKI6cC3WnwiVLecG+Ja2xRFwR3Kb33zVR20oKTgt0RXMITDEWAP/CcYjIlFR5rpnZ9frkfUdw8+UIDwfU+6jc2g==
I0521 11:23:00.893467   51396 grpc_verifier.go:796]      Data to verify signature with: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0521 11:23:00.893922   51396 grpc_verifier.go:803]      Test Signature Verified
I0521 11:23:00.894155   51396 grpc_verifier.go:824]      Unrestricted RSA Public key parameters matches AttestedCertifyInfo  true
I0521 11:23:00.894341   51396 grpc_verifier.go:839]      Issuing certificate with serialNumber 108452
I0521 11:23:00.898631   51396 grpc_verifier.go:874]      X509 issued by Verifier for unrestricted Key: 
-----BEGIN CERTIFICATE-----
MIID2jCCAsKgAwIBAgIDAaekMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAlVT
MQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJpc2UxIjAgBgNVBAMM
GUVudGVycHJpc2UgU3Vib3JkaW5hdGUgQ0EwHhcNMjMwNTIxMTUyMzAwWhcNMjMw
NTIyMTUyMzAwWjCBiTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzARBgNV
BAsTCkVudGVycHJpc2UxJjAkBgNVBAMTHW10bHMsc2VydmVyLmFub3RoZXJkb21h
aW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvE42BY3yu/og
ci+1PIAG4P39tkIyOGInFOMKJ680Csth/bcB/UXfXRq4OPVudWukwy1GwYLx2IM/
l5F3BQW9zbloW69S504l4KoRJ5OxV+Ztf91JfRo8UkffNPvpyXgJU1ZFBrqs5XVR
no8LFCEUyi89MBb6DaCbEgE2/qcf4zHs4BNle0VREz+Ag7Ph8MAhNfrethbSDt1T
8X+N/aegA/+Gd48Hzw00E/uV1ypGryrd8kUumrgt4zbt5OiRDoSsUirQQwnQP55D
Ous7eBME3vjXXmMY0bth8PaJERmABwEbcCtG1AK83z8XTytNu+9xOFW3seLth1BV
MKQh4vPelwIDAQABo3wwejAOBgNVHQ8BAf8EBAMCB4AwDwYDVR0lBAgwBgYEVR0l
ADAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFLe6sAKh5740xsEFXGZ45btTXaFU
MCgGA1UdEQQhMB+CHW10bHMsc2VydmVyLmFub3RoZXJkb21haW4uY29tMA0GCSqG
SIb3DQEBCwUAA4IBAQApFJSlAzD3UNPdTMVLMLNPIpWqs7kzGwPTzQYIomSTMtMg
Ova5Ih6TSUps6M16ytG4FQw/J+yBcqf8aOqTOj7mtGXkWx97UsnqOG6TlGlRyH/1
pcCEhvsXuSkz1gnMqVCzBibhLLVipjR2Z3bzkbnHinYl/wsD3qzSoWhT0iDOZngP
dgzjdPmNdWHhCbfKCQKq3rWdlYaySq6Hsgxf43jlVpwn6DvUJLZCvlM2UjWYKi3h
lAuQ13DiVASWMfuk8YA/NM50wE3Rr7Pq0AXubMLReebuaci2YzFAHkxr9PMZJl8X
nb+L3iVa1/DVELR5ZKOJhr6OegKFjR+KSdPO5uGK
-----END CERTIFICATE-----
I0521 11:23:00.898695   51396 grpc_verifier.go:876]      Pulled Signing Key  complete 369c327d-ad1f-401c-aa91-d9b0e69bft67
```