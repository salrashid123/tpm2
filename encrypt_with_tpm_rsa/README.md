
# TPM Sign with RSA

```bash
echo "my message" > message.dat

tpm2_createprimary -C o -c primary.ctx -Q
tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx -Q

tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_readpublic -c key.ctx  -o key.pem -f PEM -Q

cat key.pem

tpm2_sign -c key.ctx -g sha256 -o sig.rssa message.dat
tpm2_verifysignature -c key.ctx -g sha256 -s sig.rssa -m message.dat

### openssl
sha256sum message.dat | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest
tpm2_sign -Q -c key.ctx -g sha256 -d -f plain -o data.out.signed data.in.digest
openssl dgst -verify key.pem -keyform pem -sha256 -signature data.out.signed message.dat

```


---

```bash
# go run svcaccount/main.go 
======= Key persisted ========
======= Sign with new RSA ========
Signature data:  L4LkdyjpqaPWpcZXeHV9bMs0xmGRQpXMHeLuosTLxCaljpdmk9TbDGaHS1zqhUYV85ZnbqsvTgYeP0auierHXOOINBV1kbKuoihZJhsbyfmcIpIdoHItRwPM/sTH3fl4ZxcASSiZSC6F6b38Q6J75xQPqAT93Ua0n7LeWdcP/er8eed6yPISdScF/+B/45LmqT/y+3rVTlhRgBLvTm846ifL/1XzUMdcSRq3OOk0UYDNh3IfbQXTg7lFRtgo6hxy+rsUNwwy0Ip54wZXftalVx9+dfrB9ZlHW1c9KF1WObmu+noPEDlex0AoZ4sB3FtTcJj/glXZovP9KKjSjeSkTA
RSA Signing Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJamgslhqX9leS7CJGb4
sOuKhvzSYYjKpocEko3EdhrZlw4Y0ufkeCRV4IQtWe74CZvHNeXzjsf3pFDHGXs1
RMCUJ8u+By54OIMCQFBwmmg6/8lfu/WhXDY/PgdwuAocaAAYuqfj29vIxG/8Y9KX
qZJ3S8o0aP+cLX+C7lU5k/1kS5n4w2BnmUXi9jsfCJ3kBMxXduQdy4zd4Tml450x
ypcAQOI8u7qt0Xam6cMMu2wwJGvIewnkQaVY7P4o+qRRsc42wXsQ3gl8xpkjQFmO
dApWjF2olxUTh20iZfjJLyIyIJf61QC02c9evqC6Q1pHZ23+FWXc/5b9M2HvAIVl
qwIDAQAB
-----END PUBLIC KEY-----

signature Verified

```


---

for RSA PSS:

```golang
	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	}


	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rsassa, err := rspSign.Signature.Signature.RSAPSS()

	log.Printf("PSS signature: %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))

	err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer, &rsa.PSSOptions{
		Hash:       crypto.SHA256,
		SaltLength: rsa.PSSSaltLengthAuto,
	})


```
