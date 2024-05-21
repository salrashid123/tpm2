# Importing an external key and load it ot the TPM


### create rsa key 

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
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

  2023/09/04 14:29:19 ======= Flushing Transient Handles ========
  2023/09/04 14:29:19     0 handles flushed
  2023/09/04 14:29:19     Primary KeySize 256
  2023/09/04 14:29:19      tpmPub Size(): 256
  2023/09/04 14:29:19      Pub Name: 000bb902b761b853873f822265820736416f20d6c0259d21779496cb568cf0ba1a4b
  2023/09/04 14:29:19      PubPEM: 
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYGt/zWkgxIbMjRQ1iCe
  xnNOIDm8aBkQuse6PLEGrGXR4Adud9xhUsDbZdR50hg9G+K9QHpRmprhm0wl/S29
  vD7/7KZn1CLJUT8Gwmkzt8MnCMiydEv6KLoyDALoXTZG42/zn2gfXff4g6IYQtE7
  w6cK/SDDEVR8V664VaYhanqKz0qws5/SpOTjXzExh5kWCyPd2Pwo1Ca8lSXQeg/1
  79u9AeYQgvqF3k2aA/sE45i3MllzL18aHYyrh4PbWl2jPRgjDc4AiVC0MOcWw8hR
  Uz/mrsbHxzQMc5QooHm02BlW2FhDqxaeJ9k/yFN9/8eNaqxF65PaMbQBRZue4rg+
  wQIDAQAB
  -----END PUBLIC KEY-----
  2023/09/04 14:29:19 ======= Import ======= 
  2023/09/04 14:29:19 ======= Init ========
  2023/09/04 14:29:19      Imported Public digestValue: 2a9a6a1e020c3aca8ce51c497fdb385d2acf5ba48247765c4351b5852daf859f
  2023/09/04 14:29:19      Loaded Import Blob transient handle [0x80000001], Name: 0022000b2a9a6a1e020c3aca8ce51c497fdb385d2acf5ba48247765c4351b5852daf859f
  2023/09/04 14:29:19      SavePub (key.pub) ========
  2023/09/04 14:29:19      SavePriv (key.priv) ========
  2023/09/04 14:29:19      key persisted
  2023/09/04 14:29:19      LoadkeyPub (key.pub) ========
  2023/09/04 14:29:19      LoadkeyPriv (key.priv) ========
  2023/09/04 14:29:19      Loaded Import Blob transient handle [0x80000001], Name: 0022000b2a9a6a1e020c3aca8ce51c497fdb385d2acf5ba48247765c4351b5852daf859f
  2023/09/04 14:29:19 Signature data:  Sp810z...
```



```bash
$ go run importExternalRSA.go --mode=load --keyPub key.pub --keyPriv=key.priv

  2023/09/04 14:30:45 ======= Flushing Transient Handles ========
  2023/09/04 14:30:45     0 handles flushed
  2023/09/04 14:30:45     Primary KeySize 256
  2023/09/04 14:30:45      tpmPub Size(): 256
  2023/09/04 14:30:45      Pub Name: 000bb902b761b853873f822265820736416f20d6c0259d21779496cb568cf0ba1a4b
  2023/09/04 14:30:45      PubPEM: 
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYGt/zWkgxIbMjRQ1iCe
  xnNOIDm8aBkQuse6PLEGrGXR4Adud9xhUsDbZdR50hg9G+K9QHpRmprhm0wl/S29
  vD7/7KZn1CLJUT8Gwmkzt8MnCMiydEv6KLoyDALoXTZG42/zn2gfXff4g6IYQtE7
  w6cK/SDDEVR8V664VaYhanqKz0qws5/SpOTjXzExh5kWCyPd2Pwo1Ca8lSXQeg/1
  79u9AeYQgvqF3k2aA/sE45i3MllzL18aHYyrh4PbWl2jPRgjDc4AiVC0MOcWw8hR
  Uz/mrsbHxzQMc5QooHm02BlW2FhDqxaeJ9k/yFN9/8eNaqxF65PaMbQBRZue4rg+
  wQIDAQAB
  -----END PUBLIC KEY-----
  2023/09/04 14:30:45      LoadkeyPub (key.pub) ========
  2023/09/04 14:30:45      LoadkeyPriv (key.priv) ========
  2023/09/04 14:30:45      Loaded Import Blob transient handle [0x80000001], Name: 0022000b2a9a6a1e020c3aca8ce51c497fdb385d2acf5ba48247765c4351b5852daf859f
  2023/09/04 14:30:45 Signature data:  Sp810z
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