## Securely Embedding Service Account keys into Trusted Platform Modules


The following procedure transfers an RSA key from one system to another TPM such that the key on the TPM can be used to sign but is not exportable.

One usecase for this is to securely transfer any RSA key from one system to another one with a TPM.  In this specific case, we will transfer a Google Cloud Platform Service Account private key to a [Shielded VMs vTPM](https://cloud.google.com/blog/products/gcp/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext).  Once the key is imported, its set to be unexportable from the TPM but can be used to Sign data.  

Since signing some data using a Service Accounts's key is at the core of how Google Cloud Service Accounts authenticate from a client, an embedded key on the TPM can be used to authenticate to Google Cloud.

For more information, see

- [https://github.com/salrashid123/oauth2#usage-tpmtokensource](https://github.com/salrashid123/oauth2#usage-tpmtokensource)

### Setup

1. On your laptop, generate a service account key in `JSON` format:

```
 gcloud iam service-accounts keys  create svc_account.json --iam-account=service@project.iam.gserviceaccount.com 
```

Extract the PEM portion, remove the passphrase and note down the KEYID:

```bash
cat svc_account.json | jq -r '.private_key' > private.pem
openssl rsa -in private.pem -out private_nopass.pem
KEY_ID=`cat svc_account.json | jq -r '.private_key_id'`
$ echo $KEY_ID

```

2. Assign this service account IAM permissions to read pubsub topics and list buckets on a given project

3. Create a [GCP ShieldedVM](https://cloud.google.com/security/shielded-cloud/shielded-vm)
  (call the VM `tpm-a`)

4. Get its Endorsement Public key

```bash
gcloud compute instances get-shielded-identity tpm-a --format="value(encryptionKey.ekPub)" > ek.pem
```

5. Seal the service account key

On your laptop:

```cd transfer/```

```bash

$ go run laptop/main.go  \
    --rsaKeyFile=private_nopass.pem \
    --sealedOutput=sealed.dat \
    --ekPubFile=ek.pem --v=2 -alsologtostderr
```

```
$ go run laptop/main.go      --rsaKeyFile=private_nopass.pem     --sealedOutput=sealed.dat     --ekPubFile=ek.pem  --v=2 -alsologtostderr
I0314 17:00:48.672933  176804 main.go:81] ======= Init createSigningKeyImportBlob ========
I0314 17:00:48.673160  176804 main.go:83] ======= Loading ekPub ========
I0314 17:00:48.673223  176804 main.go:101] ======= Loading Service Account RSA Key ========
I0314 17:00:48.673324  176804 main.go:115] ======= Generating Test Signature ========
I0314 17:00:48.675523  176804 main.go:128] Signature: %se3TcMAqognfqeMdSukkYBAgBoHZw3td/azrH9XhzYtfABukueB3rvVvkBwHfChfY65Hja2JA4rsycJYrnD9D7M5DIsDjbQ1ZwGdvxQrFzqro9xvFL621B8teNQDESe75Gj1hrmR//xMXhN7TftB+6GgVoeyPV8WXhfpdUUw7tZG1Xygun3HCfclO4f/adtwFOB4PF8EM9YIZCaZRg2Sp7wTn7VNQ+4K5vpebblcxwvO1/gi9Wlt+oQyn1jYgMS0i1y8Ej0URlBEPumZKjpJTHJkhMxHgBSfjf/0CrkDMLgIz8mzhQraAXdBWAsL4n7PwX9t+hLcbxXYDVMwG49cxaA==
I0314 17:00:48.675538  176804 main.go:130] ======= CreateSigningKeyImportBlob for RSA Key: ========
I0314 17:00:48.675708  176804 main.go:142] ======= Saving sealedkey ========
I0314 17:00:48.675823  176804 main.go:152] Sealed data to file.. sealed.dat
```

6. Transfer `sealed.dat` to the ShieldedVM
  Use any mechanism you want; the sealed data can't get decoded anywhere other than on assigned TPM

7. Extract the selaed data and save to the TPM

On shieldedVM:

```cd transfer/```
```
 go run main.go \
  --importSigningKeyFile=sealed.dat \
  --keyHandleOutputFile=key.dat \
  --flush=all \
  --v=2 -alsologtostderr
```

```
$ sudo ./import   --importSigningKeyFile=sealed.dat   --keyHandleOutputFile=key.dat   --flush=all   --v=10 -alsologtostderr
I0314 21:05:14.931044    5943 main.go:51] ======= Init importSigningKey ========
I0314 21:05:14.945527    5943 main.go:73] Handle 0x3000000 flushed
I0314 21:05:14.948445    5943 main.go:86] ======= Loading EndorsementKeyRSA ========
I0314 21:05:14.954194    5943 main.go:93] ======= Loading sealedkey ========
I0314 21:05:14.954412    5943 main.go:104] ======= Loading ImportSigningKey ========
I0314 21:05:14.976636    5943 main.go:111] ======= Saving Key Handle========
I0314 21:05:14.987044    5943 main.go:124] ======= Loading Key Handle ========
I0314 21:05:14.995937    5943 main.go:136] ======= Signing Data with Key Handle ========
I0314 21:05:15.003742    5943 main.go:181] Test Signature: e3TcMAqognfqeMdSukkYBAgBoHZw3td/azrH9XhzYtfABukueB3rvVvkBwHfChfY65Hja2JA4rsycJYrnD9D7M5DIsDjbQ1ZwGdvxQrFzqro9xvFL621B8teNQDESe75Gj1hrmR//xMXhN7TftB+6GgVoeyPV8WXhfpdUUw7tZG1Xygun3HCfclO4f/adtwFOB4PF8EM9YIZCaZRg2Sp7wTn7VNQ+4K5vpebblcxwvO1/gi9Wlt+oQyn1jYgMS0i1y8Ej0URlBEPumZKjpJTHJkhMxHgBSfjf/0CrkDMLgIz8mzhQraAXdBWAsL4n7PwX9t+hLcbxXYDVMwG49cxaA==
```

The outputfile, `key.dat` is just a handle to the embedded key.  It does not contain the raw key material.

Instead of saving a key reference, you can also make persistent handle which means you dont' have to remember where the `key.dat` is.

8. Access GCP Services using the key on TPM

On ShieldedVM:

Compile and access either gcs or pubsub using the embedded key:

eg. using my keyID and service account/project


```bash
cd gcp/
go get cloud.google.com/go/storage github.com/golang/glog github.com/google/go-tpm/tpm2 github.com/salrashid123/oauth2/google google.golang.org/api/iterator google.golang.org/api/option


$ cat sa-3.json | jq -r '.private_key_id'
   30566a119f1f03cdb9e5c076a0aceba073b6352d

$ cat sa-3.json | jq -r '.client_email'
   sa-3-reader@shared-project-271117.iam.gserviceaccount.com
   
sudo ./gcp    --mode=gcs   --keyHandleFile=key.dat   --serviceAccountEmail=sa-3-reader@shared-project-271117.iam.gserviceaccount.com  --keyId=30566a119f1f03cdb9e5c076a0aceba073b6352d    --projectId=shared-project-271117  --bucketName=shared-project-271117-shared-bucket  --objectName=somefile.txt  --dest=somefile.txt

2020/03/14 21:20:14 Wrote 14 bytes.
```

---

## Binding to PCR values:

You can also bind unsealing the key to a set of PCR values that must exist on the target TPM.

To bind the sealed data to a set of PCR values, pass the `--pcrValues=bank1=value1,bank2=value2`

into the `transfer/remote/main.go` script as shown here:


- Laptop
```bash

go run laptop/main.go  \
  --rsaKeyFile=svc_account.p12 \
  --sealedOutput=sealed.dat \
  --ekPubFile=ek.pem \
  --pcrValues=23=F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B \
  -v=2 -alsologtostderr

I0303 07:43:45.500543  110069 main.go:83] ======= Init createSigningKeyImportBlob ========
I0303 07:43:45.500706  110069 main.go:85] ======= Loading ekPub ========
I0303 07:43:45.500761  110069 main.go:103] ======= Loading Service Account RSA Key ========
I0303 07:43:45.566058  110069 main.go:119] ======= Generating Test Signature ========
I0303 07:43:45.567500  110069 main.go:132] Signature: %sEr0UFqzpQtqX3PQjCrelMO0v+PRiGtJ8srs+AR/C6Iwf3WRV4FYuj+lzdGJjxF/udwwU+E/chCodxnHKV3tqUs9O6iNVb0OHQV64orJnkcxdf/d6XmJgH/7oY3bssVltmV4YO4a5n6YZR69TjtL+srLF+O5JeVMzFSwDgbsYFaI67BTH3Bqr2jnoL01Imrvr5cFQX2USs1S4l0EIstfGObWP8qIiSX88c1dXz/74sjYtTKMD3J++nfzGdJOA7nyss0TwRQQHP8yPJcDUnswmWlICn9mXZm2r2FW1hByDO3HenxBbjpD6iUOtABfvruBPBMZmlowKpTnrbN8c2rNP4A==
I0303 07:43:45.567510  110069 main.go:134] ======= CreateSigningKeyImportBlob for RSA Key: ========
I0303 07:43:45.567627  110069 main.go:146] ======= Saving sealedkey ========
I0303 07:43:45.567752  110069 main.go:156] Sealed data to file.. sealed.dat
```


- Shielded

```
go run main.go \
  --importSigningKeyFile=sealed.dat \
  --keyHandleOutputFile=key.dat \
  --flush=all \
  --bindPCRValue=23 \
  --v=2 -alsologtostderr


I0303 12:45:18.280628   15810 main.go:51] ======= Init importSigningKey ========
I0303 12:45:18.297643   15810 main.go:79] ======= Print PCR  ========
I0303 12:45:18.299532   15810 main.go:84] PCR: %!i(int=23) 00000000  f5 a5 fd 42 d1 6a 20 30  27 98 ef 6e d3 09 97 9b  |...B.j 0'..n....|
00000010  43 00 3d 23 20 d9 f0 e8  ea 98 31 a9 27 59 fb 4b  |C.=# .....1.'Y.K|
I0303 12:45:18.299756   15810 main.go:86] ======= Loading EndorsementKeyRSA ========
I0303 12:45:18.305773   15810 main.go:93] ======= Loading sealedkey ========
I0303 12:45:18.306091   15810 main.go:104] ======= Loading ImportSigningKey ========
I0303 12:45:18.352857   15810 main.go:135] ======= Signing Data with Key Handle ========
I0303 12:45:18.362482   15810 main.go:186] Signature: %sEr0UFqzpQtqX3PQjCrelMO0v+PRiGtJ8srs+AR/C6Iwf3WRV4FYuj+lzdGJjxF/udwwU+E/chCodxnHKV3tqUs9O6iNVb0OHQV64orJnkcxdf/d6XmJgH/7oY3bssVltmV4YO4a5n6YZR69TjtL+srLF+O5JeVMzFSwDgbsYFaI67BTH3Bqr2jnoL01Imrvr5cFQX2USs1S4l0EIstfGObWP8qIiSX88c1dXz/74sjYtTKMD3J++nfzGdJOA7nyss0TwRQQHP8yPJcDUnswmWlICn9mXZm2r2FW1hByDO3HenxBbjpD6iUOtABfvruBPBMZmlowKpTnrbN8c2rNP4A==
```


You can recall the PCR values using any tool such as `go-tpm-library` or `tpm2_tools`.  The following uses `tpm2_tools`

```bash
$ tpm2_pcrread sha256:23
    sha256:
      23: 0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
sha256:
  23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```