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
2023/07/13 12:40:19 ======= Init  ========
2023/07/13 12:40:19 0 handles flushed
2023/07/13 12:40:19      Load SigningKey and Certifcate 
2023/07/13 12:40:19      Signing PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvr8f4lOUaHIMDoC9Baq
sLs2Irh1RrKmTbgf/cWZHvhCQUT3qGGB5gqI96/efF3pCKx/KL9tYpJ7iQ3TpJhv
E8sG+bfxA3qvoDXIzO8bsAPyEp6c77UfvHkasi4cKZP2kBIURy/TwOSeZco7qU51
V10pL4kcw8J0CeDr4KKap6m4gWXcdo4rOpRMy62bBRIaxWEbPrAlotHSoD6hvtlT
W0zBhs4zFrau+85YZNuobvvkPoZho/NosLKqNZ2gb2/ueY/mU0uAPhhtHtk7KWiN
p5iSqcWHyrzU/tZ3LwiRB/vOxeQhWH3+o3BJPU0z9Dm+5fFlO6Se4hm1/S8VxYZ4
owIDAQAB
-----END PUBLIC KEY-----
2023/07/13 12:40:19      AK Signed Data using go-tpm-tools SZYhgbIjBQM8XZ6wzlMQqTqqLotzJ4z3aY15pn/dU6gCeuhE69DfbJW6GJUpoBrEE5SzZ2E7PLvQhBzhUeCpE1u5nosbrBRoAdOmpR1GdBRz7Jgi+wtnMFVCcLvB96YmUEXrQP6S/z54x+z3nDCbOG5imcBGvpUkWMdL0sMr7X3mq1M3nXItdc92Rens4vVGGvbk17UazPyiC4rXJZTN+abL7GO8nET4QUt+TtvjBeXwKXPpQVL5tfzskUkHLscyaAWMZe5F60VTc+n6Ww7U4ra5L9njYa/kJAmYw9aHfjEnN8JxGhWInZDY7sMM9xBT6pqmmoJFC5S9nw2o7DFk4w==
2023/07/13 12:40:19      Signature Verified
2023/07/13 12:40:19 akPub Name: 0001000b00050072000000100014000b0800000000000100b6fafc7f894e51a1c8303a02f416aab0bb3622b87546b2a64db81ffdc5991ef8424144f7a86181e60a88f7afde7c5de908ac7f28bf6d62927b890dd3a4986f13cb06f9b7f1037aafa035c8ccef1bb003f2129e9cefb51fbc791ab22e1c2993f6901214472fd3c0e49e65ca3ba94e75575d292f891cc3c27409e0ebe0a29aa7a9b88165dc768e2b3a944ccbad9b05121ac5611b3eb025a2d1d2a03ea1bed9535b4cc186ce3316b6aefbce5864dba86efbe43e8661a3f368b0b2aa359da06f6fee798fe6534b803e186d1ed93b29688da79892a9c587cabcd4fed6772f089107fbcec5e421587dfea370493d4d33f439bee5f1653ba49ee219b5fd2f15c58678a3
2023/07/13 12:40:19      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
2023/07/13 12:40:19      AK Signed Data using go-tpm SZYhgbIjBQM8XZ6wzlMQqTqqLotzJ4z3aY15pn/dU6gCeuhE69DfbJW6GJUpoBrEE5SzZ2E7PLvQhBzhUeCpE1u5nosbrBRoAdOmpR1GdBRz7Jgi+wtnMFVCcLvB96YmUEXrQP6S/z54x+z3nDCbOG5imcBGvpUkWMdL0sMr7X3mq1M3nXItdc92Rens4vVGGvbk17UazPyiC4rXJZTN+abL7GO8nET4QUt+TtvjBeXwKXPpQVL5tfzskUkHLscyaAWMZe5F60VTc+n6Ww7U4ra5L9njYa/kJAmYw9aHfjEnN8JxGhWInZDY7sMM9xBT6pqmmoJFC5S9nw2o7DFk4w==
2023/07/13 12:40:19      Signature Verified

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