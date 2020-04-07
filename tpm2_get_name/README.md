# Get AK/EK "Name"

Sample program that uses the PEM format of a Key to get its "name" for attestation.


To use, get the the RSA Public key for ak or ek.


```bash
$ more akPub.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy47TSu7IgPqdgcf8Ac5X
zLRWY1KrnLJp/kGtxnQ4YMrHSlDbUuH8Pz1OWRZ9Bs2pykqNOKj9huXWs+nUuxBe
fZ+xfx5UdKmd4tPDxWbBT+ViQasvaldKzWiqqJ0sx7Iwl4uamQwYpzeG6qtQSMsx
Pe5zGwdmpjyoiufNCkl7LiGCLGb8IgBLVWUNDNnHA7h+J8Pqz36xSBXJgcACq5Bj
Dljrx9KYmt66EgRbSO5j7Yij7CEfKeSvtdOK31qAwGzXZA0kg2XvFLI+of5cVX5o
0Jzt6AiSjNPcssZ44dgCj5ZaHTFTFRk643pWzFhG2m7KMqmU+6yXgRZY6uTOtfO1
dwIDAQAB
-----END PUBLIC KEY-----

$ sudo ./getname
2020/04/07 14:17:38 ======= Init  ========
2020/04/07 14:17:38 0 handles flushed
2020/04/07 14:17:38 akPub Name: 000b5249027ab700727b36c463e3f202b27248320dad8f7fe7fe6ceeaaa5556b637c
```