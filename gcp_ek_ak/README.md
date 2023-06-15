### Read EK keys on GCE



### using tpm2_tools
```bash
tpm2_createek -c ek.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c ek.ctx -o ek.pem -f PEM -Q

cat ek.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
uwIDAQAB
-----END PUBLIC KEY-----
```

todo: read from the nv via template
```
const GceAKTemplateNVIndexRSA uint32 = 0x01c10001 // 29425665
const GceAKCertNVIndexRSA uint32 = 0x01c10000 // 29425664
```

```
# tpm2_nvreadpublic 
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
$ gcloud compute instances get-shielded-identity attestor
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


### using go-tpm-tools

```bash
$ go run main.go 

client.EndorsementKeyRSA 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
uwIDAQAB
-----END PUBLIC KEY-----

client.GceAttestationKeyRSA 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvr8f4lOUaHIMDoC9Baq
sLs2Irh1RrKmTbgf/cWZHvhCQUT3qGGB5gqI96/efF3pCKx/KL9tYpJ7iQ3TpJhv
E8sG+bfxA3qvoDXIzO8bsAPyEp6c77UfvHkasi4cKZP2kBIURy/TwOSeZco7qU51
V10pL4kcw8J0CeDr4KKap6m4gWXcdo4rOpRMy62bBRIaxWEbPrAlotHSoD6hvtlT
W0zBhs4zFrau+85YZNuobvvkPoZho/NosLKqNZ2gb2/ueY/mU0uAPhhtHtk7KWiN
p5iSqcWHyrzU/tZ3LwiRB/vOxeQhWH3+o3BJPU0z9Dm+5fFlO6Se4hm1/S8VxYZ4
owIDAQAB
-----END PUBLIC KEY-----

client.AttestationKeyRSA 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxYhq/z0G60GKbVBY6kPr
ijJi85Tl5tAGLCW0uq7zFQ4ZNDVfAZoGxLj2aGr7bswz9mJIUfXrIfNwOZvVYZ9p
NH5QzHVXIeA4bOr/kzYWH1J+vYCF0Opinhkl46SsamtEZzWgC8VwNt+bFA5gLnHh
axOas5CoW0JEmuDAwQnTuKb4QWb3mUj3EYDyO3wsrD6gAuhiU0rnoWEsVyR59nqc
x4hWVTsPkA2qK/uDxJZgaQkScUTYII1jbizpupW/YtY8u+ehe4dkSpJPFdZiFzLF
FpNdAu+Eo3jV5U+p/k4pxsBYMc6hlKnlzeqilMGak2mOOkoXHSNaHtQ/RtTMRu49
7QIDAQAB
-----END PUBLIC KEY-----

```