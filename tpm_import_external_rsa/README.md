# Importing an external key


1) Generate RSA keypair and export the public key (can be done anywhere)
```
    $ openssl genrsa -out private.pem 2048
    $ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

2) Create a secret you want decrypted on the TPM

```
    $ echo "thepassword" > secrets.txt
```

3) Encrypt the secret using the DEK then encrypt the DEK with the RSA key

```
    openssl rsautl -encrypt -inkey public.pem -pubin -in secrets.txt -out secrets.txt.enc
```

4) On the ShieldedVM, import the external RSA keypair

```

  tpm2_createprimary -C e -c primary.ctx
        name-alg:
        value: sha256
        raw: 0xb
        attributes:
        value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt
        raw: 0x30072


    tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.priv
        name-alg:
        value: sha256
        raw: 0xb
        attributes:
        value: userwithauth|decrypt|sign
        raw: 0x60040
```

    >> You can safely delete the private.pem 



5) Sometime later on the shieldedVM, load the TPM key context file 

```
        $ tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
```

6) Use the TPM to decrypt the encrypted AES key

```
        $ tpm2_rsadecrypt -c key.ctx -o secrets.txt.ptext secrets.txt.enc
```

# more secrets.txt.ptext
thepassword
