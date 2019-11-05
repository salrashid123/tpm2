
TODO: Figure out how to use `tpm2_tools` to wrap a key with ekPub and have it decrypted on TPM

- https://github.com/google/go-tpm-tools/blob/master/server/import_test.go#L35


This `go-tpm` routine transfers a small amount of data ('hello world') from one TPM to another using just eh ekPub in PEM format.

The importblob contains is keyedHash with the inner secret encrypted by ekPub.  The target TPM will unwrap the ssecret and ultimately show the original encrypted data.

It is assumed the ekPub is trusted and in posession on the source TPM.  On Google cloud platform, ShieldedVM have vTPMs for which you can remotely use the gcloud cli to get the ekPub:

```
$ gcloud compute instances get-shielded-identity shielded-1 --format="value(encryptionKey.ekPub)" > ek.pem
```

Sample usage:
To transfer data from TPM-A to TPM-B, Copy the provided `main.go` to both systems and compile.

- on TPM-A:

Wrap the secret
```
go run main.go  --mode=seal --secret "hello world" --ekPubFile=ek.pem --sealedDataFile=sealed.dat --logtostderr=1 -v 5
```

Copy sealed.dat to TPM-B

- on TPM-B

```
sudo ./main --mode=unseal --sealedDataFile=sealed.dat --logtostderr=1 -v 5
```

