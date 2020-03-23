


This `go-tpm` routine transfers a small amount of data (eg. symmetric key) from one TPM to another using just eh ekPub in PEM format.

In this flow:
1. Seal the symmetric key using a TPM's ekPub file
2. Transfer the sealed blob to the VM instance
3. Unseal the blob on the TPM
  (optionally set a pcr value on step 1. and only allow unsealing if the pcr value matches)

The `importblob` contains is keyedHash with the inner secret encrypted by ekPub.  The target TPM will unwrap the ssecret and ultimately show the original encrypted data.

It is assumed the ekPub is trusted and in possession on the source TPM.  On Google cloud platform, ShieldedVM have vTPMs for which you can remotely use the gcloud cli to get the ekPub:


Sample usage:
To transfer data from a latop to TPM-B, Copy the provided `main.go`, `go.sum`, `go.mod` to both systems and compile.

### On laptop

Get the instance `ekPub`:

```
$ gcloud compute instances get-shielded-identity shielded-1 --format="value(encryptionKey.ekPub)" > ek.pem
```

Wrap the secret
```
$ go run main.go  --mode=seal --secret "hello world" --ekPubFile=ek.pem --sealedDataFile=sealed.dat --logtostderr=1 -v 5
I0318 14:46:10.757404   17980 main.go:94] Sealed data to file.. sealed.dat
```

Copy sealed.dat to TPM-B

### On Shielded VM:

```
# ./main --mode=unseal --sealedDataFile=sealed.dat --logtostderr=1 -v 5
I0318 18:53:05.341533    7322 main.go:124] Unsealed secret: hello world
```

