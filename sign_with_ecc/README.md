
# TPM Sign with ECC

```bash
tpm2_createprimary -C e -c primary.ctx
tpm2_create -G ecc -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c key.ctx 0x81008002   

echo "my message" > message.dat
tpm2_sign -c key.ctx -g sha256 -o sig.ecc message.dat
tpm2_verifysignature -c key.ctx -g sha256 -s sig.ecc -m message.dat
```


---

```
# go run main.go 


```