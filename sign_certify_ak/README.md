


Certify a Child Key with an AK.

1. Generate EK
2. Generate AK
3. Generate Child Key (k1) of EK that is unrestricted (`tpm2.FlagRestricted`)
4. Certify `k1` with AK
5. Verify Certification  (note, [go-tpm/issues/262](https://github.com/google/go-tpm/issues/262))

At step 6, since you confirmed AK signed k1 and if you trust AK, you can trust the signature done by `k1` in step 4


>> TODO: it would be better if `k1` is a child of AK but i could not figure that part out....


```bash
$ go run main.go 



```