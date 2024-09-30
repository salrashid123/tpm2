### Read EK keys on GCE



```bash
 gcloud compute instances create instance-cc \
     --zone=us-central1-a \
     --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan" \
     --shielded-secure-boot --no-service-account --no-scopes \
     --shielded-vtpm \
     --shielded-integrity-monitoring \
     --confidential-compute

 $  gcloud compute instances get-shielded-identity  instance-cc

## to read the ekcert from the index
 TPM2_AKCERT_NV_INDEX=0x1c10000
 tpm2_nvreadpublic | sed -n -e "/""$TPM2_AKCERT_NV_INDEX""/,\$p" | sed -e '/^[ \r\n\t]*$/,$d' | grep "size" | sed 's/.*size.*://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]$//'
   1516
 tpm2_nvread -s 1516  -C o $TPM2_AKCERT_NV_INDEX |  openssl x509 --inform DER -text -noout  -in -
```


### using tpm2_tools
```bash
tpm2_createek -c ek.ctx -G rsa -u ek.pub 
tpm2_readpublic -c ek.ctx -o ek.pem -f PEM -Q

cat ek.pem 
```

```golang
const GceAKTemplateNVIndexRSA uint32 = 0x01c10001 // 29425665
const GceAKCertNVIndexRSA uint32 = 0x01c10000 // 29425664
```

```bash
$ tpm2_nvreadpublic 
0x1c10000:
  name: 000bc1dcc77bde4982d4817bcbe8418d49c1f24e3a017e79e1be9d25f6bc50c0f7c2
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: ppwrite|writedefine|ppread|ownerread|authread|no_da|written|platformcreate
    value: 0x62072001
  size: 1516

0x1c10001:
  name: 000b13c9615918f396faf0ac6e33167b022ee40b0ed904085441fd1a80693957c234
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: ppwrite|writedefine|ppread|ownerread|authread|no_da|written|platformcreate
    value: 0x62072001
  size: 280

0x1c10003:
  name: 000b1527583d660f6f6d1543c4b4bb7af086110bc63909cf34fd1f697e12eed2e435
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: ppwrite|writedefine|ppread|ownerread|authread|no_da|written|platformcreate
    value: 0x62072001
  size: 88

tpm2_nvread -s 280  -C o 0x01c10001 -o eksigntemplate.dat
```


### using gcloud cli

```bash
$ gcloud compute instances get-shielded-identity instance-cc

encryptionKey:
  ekCert: |
    -----BEGIN CERTIFICATE-----
    MIIF6TCCA9GgAwIBAgIUAMStf+N+uiNFNTGXvUCUB94g/xIwDQYJKoZIhvcNAQEL
    BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
    Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
    b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
    NDA1MDgxMTI5MDRaGA8yMDU0MDUwMTExMjkwM1owbTEWMBQGA1UEBxMNdXMtY2Vu
    dHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMRYwFAYDVQQL
    Ew1zcmFzaGlkLXRlc3QyMRswGQYDVQQDExI1MTExMzMwNjE1ODI2MTAxNzcwggEi
    MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtTp3yrHeM1hzNT9hQ7CDJaBJB
    K9FGJNXn3reV9QVORst+ZvEJuyPKxUyklMOx47olOc3uiCZEvwCOAp7ezAeTqx8z
    X+lWdMtFvp8YA1TTjfLwnd1TJGDqfdvaZR9t8Jwft9bBUwiTpmnPBDmXghvAPuDk
    RZkNNWTI80LXYxkUWjOTnTqA9AlZfPMzs34OrS2OQqEGTKB7CIqH6djzCaBtHfXH
    f+SnyxK2osRtaCy2lkoSrbQAm7H80V3Cpe1JGbBuJUOrAiyfmquYQI1bQ5nflZiY
    ZVqMA5x2VdxZTN7KHiXju630ZtiycBfySTGl9Dh9McfCaE1J9LhPBDAMFIz7AgMB
    AAGjggFjMIIBXzAOBgNVHQ8BAf8EBAMCBSAwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
    FgQUkQmF6by+ZA8sy1c1V/Da2v0OXoEwHwYDVR0jBBgwFoAUZ8O73ljj1lF2j7Ma
    PtsHp+yTeuQwgY0GCCsGAQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9w
    cml2YXRlY2EtY29udGVudC02NWQ1M2IxNC0wMDAwLTIxMmEtYTYzMy04ODNkMjRm
    NTdiYjguc3RvcmFnZS5nb29nbGVhcGlzLmNvbS8wYzNlNzllYjA4OThkMDJlYmIw
    YS9jYS5jcnQwbwYKKwYBBAHWeQIBFQRhMF8MDXVzLWNlbnRyYWwxLWECBgCk6UWf
    4AwNc3Jhc2hpZC10ZXN0MgIIBxfoz7iW3wEMC2luc3RhbmNlLWNjoCAwHqADAgEA
    oQMBAf+iAwEB/6MDAQEApAMBAQClAwEBADANBgkqhkiG9w0BAQsFAAOCAgEAeuUM
    AO4h4WeDFYS0sT3hROXg/Kzj5gZDD1FZC+voe8nqUi1bPAJ9TiWYScI6KPlI6pgy
    7JxuNm2FHmHpu3RX+YzBtXvguC4lulLGo8RE0zRhOKzvy6gq3eKblrfreHHoUdCF
    2Ju4teYT+IbZUMya44eRm3VqmLRDSrDAdJpegYgTfNbOeAShtvRWqkq/3mkPocQp
    VDgAOSVqz0t0fhhIwuYLwpPuJqEzRCVmcIY9dBHIQUBbD82SmwMFeCKfd/syvjXr
    84AqmL2y+xvVz8C8pjKWzM70S8iHfZr0hC532c7hOAaVNPFgPZFJniJV2jBM1tQY
    MweHPnq7YIp3Pp18k0ec8YvXvYuHBMIw+qWE0tdHrKPiDD8lgZAhXXnOf8+QuLl7
    UZ+8FdjMxG5mn/CQPMng4GojBEMK+ZfL5VM+L0mBYPg4LxSsFRMhIsITNXR1z8HV
    0yRGyzPmMGEhqv3x4DzARsfC2fmOfirWbNfY3pnzPfNeWV5XPXlk6clhYJIklN0X
    5WVp2WmX9cY5F8ZTbrQZFm3KZmI3WB+JbcSTXChE7RJQtn1qTU77Z1jiS7D7vzsh
    l8wiu6P+1duFm4iHqQLTkPNQAzZieMYcGutzGuWTDbf7cP/Wg4/fAImUh/ENgzJs
    3TclDZMd8oy+WSUa9KeNTdNV9Nxp74u/1q3f1zY=
    -----END CERTIFICATE-----
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7U6d8qx3jNYczU/YUOwg
    yWgSQSvRRiTV5963lfUFTkbLfmbxCbsjysVMpJTDseO6JTnN7ogmRL8AjgKe3swH
    k6sfM1/pVnTLRb6fGANU043y8J3dUyRg6n3b2mUfbfCcH7fWwVMIk6ZpzwQ5l4Ib
    wD7g5EWZDTVkyPNC12MZFFozk506gPQJWXzzM7N+Dq0tjkKhBkygewiKh+nY8wmg
    bR31x3/kp8sStqLEbWgstpZKEq20AJux/NFdwqXtSRmwbiVDqwIsn5qrmECNW0OZ
    35WYmGVajAOcdlXcWUzeyh4l47ut9GbYsnAX8kkxpfQ4fTHHwmhNSfS4TwQwDBSM
    +wIDAQAB
    -----END PUBLIC KEY-----
kind: compute#shieldedInstanceIdentity
signingKey:
  ekCert: |
    -----BEGIN CERTIFICATE-----
    MIIF6DCCA9CgAwIBAgITd8Qu+l4xIAJND4fAVtCM6GEVoDANBgkqhkiG9w0BAQsF
    ADCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
    DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFTATBgNVBAsTDEdv
    b2dsZSBDbG91ZDEeMBwGA1UEAxMVRUsvQUsgQ0EgSW50ZXJtZWRpYXRlMCAXDTI0
    MDUwODExMjkwNFoYDzIwNTQwNTAxMTEyOTAzWjBtMRYwFAYDVQQHEw11cy1jZW50
    cmFsMS1hMR4wHAYDVQQKExVHb29nbGUgQ29tcHV0ZSBFbmdpbmUxFjAUBgNVBAsT
    DXNyYXNoaWQtdGVzdDIxGzAZBgNVBAMTEjUxMTEzMzA2MTU4MjYxMDE3NzCCASIw
    DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANKG5qDpSUZEUUxrJ6+SrwFFQ3K9
    EUsZbZze1aV2kZ2dPuH5iMdxR8hchX26dcNWo8wgiaCH/HBi4fH5+I6hdfPwLzUw
    uXnpsIU4cjI6KjKRajlrPVNmeLxNyK38//guPLQy9/WNBa+ngbuYMmrNxMNipwqG
    L7ql1jWEYBOlNfq4Lo//scnI7Qe1UCIwXWvIw746qkXKnv96OhtmU3BLHdgZrkXi
    2nkXfP5XKl94/PezzYiVU17kEVXnrVDOomspD+k2EIQVUAxoD35EWULZxXS5PwHT
    P2SUPxiZ1vtbmWeY7AYuYekpG6KjghEclxFuDOiWz0QuMxjb89B5Out6kpECAwEA
    AaOCAWMwggFfMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
    BBSAZdimnJWcVzMDvhXc5QgGflBmQTAfBgNVHSMEGDAWgBQEbnNYMsSlysI5BP4z
    e1lAYGjItDCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3By
    aXZhdGVjYS1jb250ZW50LTY1ZDcwM2M0LTAwMDAtMmJiNS04YzYwLTI0MDU4ODcy
    N2E3OC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzE0MTI4NGMxMThlZWRhZWMwOWY5
    L2NhLmNydDBvBgorBgEEAdZ5AgEVBGEwXwwNdXMtY2VudHJhbDEtYQIGAKTpRZ/g
    DA1zcmFzaGlkLXRlc3QyAggHF+jPuJbfAQwLaW5zdGFuY2UtY2OgIDAeoAMCAQCh
    AwEB/6IDAQH/owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQB/VkLM
    xyELCTixIALvqAozQqfNuOh9d6cNnVcBBUv3SV8CSKLP/YWcvVR2IOvDIPBj+PcR
    F1A6vQWFsiDiCuFx3nOuy1Co9G9Kb68EMNcMF4TqbrX4EUDvMbZZGrBawMJ4jXct
    UDw3bwQOOJg8eB3cOzyzJM9RRzlPfLClWaTbPMAsJ1gZmyxLnrvqW7B3zgQ9NBOg
    LSDAdGD1s74mQM52vwlRapqbwQfrMPZWrIdyp+rWKL/3Q3XDaEJofgDuJCKhnoRQ
    IJDK/MyCjzCM/UO6E70RBicIPAFJSanvM+DbrK4ivO6l92AkPolDAkatSJNSQZNh
    CgCCVJLzzX2jWLf9Y39R5oewx27J8vCmbJa3L/jl9ZrFCgEZolEpiTq+Xl3BlDPr
    d1m32g/zVP5YvPfO3Krx0eMEEUPE0EY+9KCz75RGEZKHkNeRN2b36F+w5BvFYuLp
    cI0sfnnR997Gv9Da3xoXXraOYAQe56+AP/fwBEAeLqK2QqQ0wzAa0fTVFoNQDuyL
    zIT+fXNCcj369Sgj9NtFD0l+/ndLpXnf+hC8Nk67AbMAKjcTHRVRDK5nQNME23oW
    42OtkVLMb3dlymL+lh9BkCSxh232co26PTc4MumILGjNr9CLaAHdOrqRKTS7G66u
    qIPDal8msW/+EAr4Eks27BMhyeca7IO/u9BeNw==
    -----END CERTIFICATE-----
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0obmoOlJRkRRTGsnr5Kv
    AUVDcr0RSxltnN7VpXaRnZ0+4fmIx3FHyFyFfbp1w1ajzCCJoIf8cGLh8fn4jqF1
    8/AvNTC5eemwhThyMjoqMpFqOWs9U2Z4vE3Irfz/+C48tDL39Y0Fr6eBu5gyas3E
    w2KnCoYvuqXWNYRgE6U1+rguj/+xycjtB7VQIjBda8jDvjqqRcqe/3o6G2ZTcEsd
    2BmuReLaeRd8/lcqX3j897PNiJVTXuQRVeetUM6iaykP6TYQhBVQDGgPfkRZQtnF
    dLk/AdM/ZJQ/GJnW+1uZZ5jsBi5h6SkboqOCERyXEW4M6JbPRC4zGNvz0Hk663qS
    kQIDAQAB
    -----END PUBLIC KEY-----

```


### using go-tpm-tools

```bash
$ go run main.go 

go run main.go 
2024/09/30 11:38:07 ======= Read NV for GCE ak ========
2024/09/30 11:38:07 Name: 000b13c9615918f396faf0ac6e33167b022ee40b0ed904085441fd1a80693957c234
2024/09/30 11:38:07 Size: 280
2024/09/30 11:38:07 TPM Max NV buffer 2048
2024/09/30 11:38:07 GCE AKPublic: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0obmoOlJRkRRTGsnr5Kv
AUVDcr0RSxltnN7VpXaRnZ0+4fmIx3FHyFyFfbp1w1ajzCCJoIf8cGLh8fn4jqF1
8/AvNTC5eemwhThyMjoqMpFqOWs9U2Z4vE3Irfz/+C48tDL39Y0Fr6eBu5gyas3E
w2KnCoYvuqXWNYRgE6U1+rguj/+xycjtB7VQIjBda8jDvjqqRcqe/3o6G2ZTcEsd
2BmuReLaeRd8/lcqX3j897PNiJVTXuQRVeetUM6iaykP6TYQhBVQDGgPfkRZQtnF
dLk/AdM/ZJQ/GJnW+1uZZ5jsBi5h6SkboqOCERyXEW4M6JbPRC4zGNvz0Hk663qS
kQIDAQAB
-----END PUBLIC KEY-----
2024/09/30 11:38:07 ======= createPrimary RSAEKTemplate ========
2024/09/30 11:38:07 Name 000b9a04eaa73cc7ed6556b8874ea2eade41b9f564b024ef98782065192542e1fc33
2024/09/30 11:38:07 GCE EKPublic: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7U6d8qx3jNYczU/YUOwg
yWgSQSvRRiTV5963lfUFTkbLfmbxCbsjysVMpJTDseO6JTnN7ogmRL8AjgKe3swH
k6sfM1/pVnTLRb6fGANU043y8J3dUyRg6n3b2mUfbfCcH7fWwVMIk6ZpzwQ5l4Ib
wD7g5EWZDTVkyPNC12MZFFozk506gPQJWXzzM7N+Dq0tjkKhBkygewiKh+nY8wmg
bR31x3/kp8sStqLEbWgstpZKEq20AJux/NFdwqXtSRmwbiVDqwIsn5qrmECNW0OZ
35WYmGVajAOcdlXcWUzeyh4l47ut9GbYsnAX8kkxpfQ4fTHHwmhNSfS4TwQwDBSM
+wIDAQAB
-----END PUBLIC KEY-----



```