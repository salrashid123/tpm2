# Importing an external key and load it ot the TPM


### create rsa key 

```bash

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out private.pem

```

## using tpm2_tools

```bash
	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81010002



### remove prior handles (if any)
tpm2_getcap handles-persistent
	  -   0x81010002

# to actually remove
tpm2_evictcontrol -C o -c 0x81010002

```


### create 

```bash
$ go run importExternalRSA.go --mode=create --keyPub key.pub --keyPriv=key.priv --pemFile=private.pem --handle=0x81010002


```




---

```bash
# more private.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6T5pb0vvy8qBI00VnqZDDQt7qfAS4+fTnpLo+xFRwseUhe8D
MD8PFreK54fRU8U7vHRc6fcx3qL0GxikdXU5q524SodNi7xV5peCi2jNNoQS0gHI
2VVPtmQqHqGiJN1H5SqKhtJAMPJsx5vS4edxzijX/DcbBP5kMbcLqc8iaH3M65jY
yx8entT0U33boceRDhJWUerrNb0OUItOPStQPnj6BjMQim5mWsK/u8DD0eN1stMM
Nc2QV14Nv9gn/dtDpe24El/730oU7JRB1X2NuUNlhU5BLBhdaAbCvA9oJr1yTO+y
v/zVTWNTCQTPk2KG533EWsPy5slWOy7KStfD/QIDAQABAoIBAFxhSNc5B1f689zs
egSlK2duReOP35t+xXVIEJjoSi7QZ4YInYWtZCeGOLDtPT5lnvxMRkSwkILynaZh
wzl2XYoYZNa38kHHLWqwVZcrwiO2edHNvSQ/Qtwlnf0V3aemMQSWLdmqSpxYWDdT
A1pQFeYmjS0rEjuPGlYKfscZ8DHb6AkVdTcJ2pZBPUuKB+lPKnI+i5W+7CeJTw2T
lUqsFAS9rWxQDZxczvXmLk/Jm68LFS4I05tB7PFfUkublMdLUc3ck80meaCOeHcN
HCSm89xecJwwHSL2UnDZ3jxu/O4w9mA4u5Q5M2bJQY/ijrd233tpOMTBATWMZ4UX
mWZUnK0CgYEA980AmrTb/M9WXb7ZAxmbCC9qcYzhAWK6F64eyFZl7g1RjJMtSZHd
plDq8KaT4SC6T/KuJXt2bCiFVDLXmE7V3fkhc8rUm1oM74GGCsZKWmtwgFUcRkNT
ryqOnwvx2+jmlRnbF9dgmQeo9ZkOa6dc299qdEf+zAzd99VFHYhcOtMCgYEA8PYa
utedfF3Z3CIHbTSKHLQ8yfhyXiM89/ePb/6QxTaDKB3ESAbuT+o7fyNMlrSGsNRz
bgU2AudzGGslQ/sKPRlZrZVs9Bohq0vGpq9inTQ3x1QRV452iU2wo/7ifN/DJzw4
z+t4+xdqz5gP44MwLQQakd22WTuuEqZDoqlGI+8CgYBXr+Rx2mQqPthqDfnPHgV9
TQIWsmqAygXeEVB1RhWFupLL8tzItuQ/UU0B4YBc3u7vEYpMWzcZqPEdTWx7ShJm
HR2YUwMPAjunmSbssyRmgLRrxTJfLr3zM1UKtPheADlwM5kTA7T8EfjZB9NRhwTW
DWYnRb7FSBxX8dEmVTWF3wKBgCpgvha6MQJcZyJmAbRdFyUxNbe3sDWKMQDTUzC5
LrDgg3Sct5aLUYJQiaI0jRW8LiwPUTW6SON93SogPe+UyRoxySnUK9NKfT1pGEjc
c5V+R4kQ6fPiJErFlRlijGa129acqsk2epJ+bdSQw8qZmfFw1VNuENHkwxqYjzCe
YK2VAoGBAJJLsLrmFAse7xUVzo4E7gDHIQW42OQRdW7rY5dWT1fWSZWqBlDox2mU
JMohPgZdTlq/7Umb6O0nqRxAJT04381RKw+DxsQzMnKRDkc2gNe5qzBMKbdkSB6g
R/C+mWqI7iiyT1xZSJK5Z1Fm/Hk688nzA1WOXKozwmNU4b3ANekA
-----END RSA PRIVATE KEY-----
```