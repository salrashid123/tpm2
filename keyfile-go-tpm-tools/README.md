

## go-tpm-tools.client.Key compatibility with go-keyfile

the following will 

0. create a primary key with password
1. create a key using `go-tpm` password
2. use save it to disk as `TSS PRIVATE KEY` using `go-keyfile`
3. generate a test signature using `go-tpm`
4. close tpm
5. reload the key from file using `go-keyfile`
6. construct a `go-tpm-tools.client.Key`
7. skip generate a test signature using `go-tpm-tools` (because go-tpm singers expects null password)
8. convert `go-tpm-tools.client.Key` values for use with `go-tpm`
9. generate a test signature using `go-tpm` with transport encryption 


