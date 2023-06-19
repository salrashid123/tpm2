Sign with AK saved to NV


https://pkg.go.dev/github.com/google/go-tpm-tools/client#EndorsementKeyFromNvIndex




for GCE VMs

```golang
const (
	tpmDevice             = "/dev/tpm0"
	signCertNVIndex       = 0x01c10000
	signKeyNVIndex        = 0x01c10001
	encryptionCertNVIndex = 0x01c00002
	emptyPassword         = ""
)
```

---

```bash
# go run main.go 

go run main.go 
2023/06/19 16:31:43 ======= Init  ========
2023/06/19 16:31:43 0 handles flushed
2023/06/19 16:31:43      Load SigningKey and Certifcate 
2023/06/19 16:31:43      Signing PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvr8f4lOUaHIMDoC9Baq
sLs2Irh1RrKmTbgf/cWZHvhCQUT3qGGB5gqI96/efF3pCKx/KL9tYpJ7iQ3TpJhv
E8sG+bfxA3qvoDXIzO8bsAPyEp6c77UfvHkasi4cKZP2kBIURy/TwOSeZco7qU51
V10pL4kcw8J0CeDr4KKap6m4gWXcdo4rOpRMy62bBRIaxWEbPrAlotHSoD6hvtlT
W0zBhs4zFrau+85YZNuobvvkPoZho/NosLKqNZ2gb2/ueY/mU0uAPhhtHtk7KWiN
p5iSqcWHyrzU/tZ3LwiRB/vOxeQhWH3+o3BJPU0z9Dm+5fFlO6Se4hm1/S8VxYZ4
owIDAQAB
-----END PUBLIC KEY-----
2023/06/19 16:31:43      AK Signed Data using go-tpm-tools SZYhgbIjBQM8XZ6wzlMQqTqqLotzJ4z3aY15pn/dU6gCeuhE69DfbJW6GJUpoBrEE5SzZ2E7PLvQhBzhUeCpE1u5nosbrBRoAdOmpR1GdBRz7Jgi+wtnMFVCcLvB96YmUEXrQP6S/z54x+z3nDCbOG5imcBGvpUkWMdL0sMr7X3mq1M3nXItdc92Rens4vVGGvbk17UazPyiC4rXJZTN+abL7GO8nET4QUt+TtvjBeXwKXPpQVL5tfzskUkHLscyaAWMZe5F60VTc+n6Ww7U4ra5L9njYa/kJAmYw9aHfjEnN8JxGhWInZDY7sMM9xBT6pqmmoJFC5S9nw2o7DFk4w==
2023/06/19 16:31:43      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
2023/06/19 16:31:43      AK Signed Data SZYhgbIjBQM8XZ6wzlMQqTqqLotzJ4z3aY15pn/dU6gCeuhE69DfbJW6GJUpoBrEE5SzZ2E7PLvQhBzhUeCpE1u5nosbrBRoAdOmpR1GdBRz7Jgi+wtnMFVCcLvB96YmUEXrQP6S/z54x+z3nDCbOG5imcBGvpUkWMdL0sMr7X3mq1M3nXItdc92Rens4vVGGvbk17UazPyiC4rXJZTN+abL7GO8nET4QUt+TtvjBeXwKXPpQVL5tfzskUkHLscyaAWMZe5F60VTc+n6Ww7U4ra5L9njYa/kJAmYw9aHfjEnN8JxGhWInZDY7sMM9xBT6pqmmoJFC5S9nw2o7DFk4w==
2023/06/19 16:31:43      Signature Verified
```


Note the signingKey public cert is matches the one derived from the ek in NVRAM

```bash
$ $ gcloud compute instances get-shielded-identity attestor

encryptionKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
    tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
    ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
    WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
    ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
    BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
    uwIDAQAB
    -----END PUBLIC KEY-----
kind: compute#shieldedInstanceIdentity
signingKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvr8f4lOUaHIMDoC9Baq
    sLs2Irh1RrKmTbgf/cWZHvhCQUT3qGGB5gqI96/efF3pCKx/KL9tYpJ7iQ3TpJhv
    E8sG+bfxA3qvoDXIzO8bsAPyEp6c77UfvHkasi4cKZP2kBIURy/TwOSeZco7qU51
    V10pL4kcw8J0CeDr4KKap6m4gWXcdo4rOpRMy62bBRIaxWEbPrAlotHSoD6hvtlT
    W0zBhs4zFrau+85YZNuobvvkPoZho/NosLKqNZ2gb2/ueY/mU0uAPhhtHtk7KWiN
    p5iSqcWHyrzU/tZ3LwiRB/vOxeQhWH3+o3BJPU0z9Dm+5fFlO6Se4hm1/S8VxYZ4
    owIDAQAB
    -----END PUBLIC KEY-----

```