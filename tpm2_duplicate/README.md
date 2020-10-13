## TPM2_DUPLICATE


See: [Duplicating-Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)


# Duplicating Objects

Sample procedure to transfer an RSA key from one TPM to another. The RSA key
never leaves the protection of the two TPMs at anytime and cannot be decoded or
used on any other system even if it intercepted in transit.


This procedure will transfer an RSA key from `TPM-A` to `TPM-B`.  The key can be
generated via `openssl` and imported into `TPM-A` or generated directly on
`TPM-A`.

`TPM-B` will provide `TPM-A` the public portion of a keypair it owns that allows
a sealed transfer.  This tutorial uses the following two APIs

* [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md)
* [tpm2_import](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md)


## On TPM-B

Create a parent object that will be used to wrap/transfer the PEM file
```
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_create  -C primary.ctx -g sha256 -G rsa \
-r new_parent.prv  -u new_parent.pub \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"
```

Copy `new_parent.pub` to `TPM-A`.  The copy steps assumes attestation was done
previously and that `TPM-A` trusts the `new_parent.pub` issued by `TPM-B`

## On TPM-A

Create root object and auth policy allows duplication only

```
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_startauthsession -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate

tpm2_flushcontext session.dat

rm session.dat
```

Generate an RSA keypair on TPM to transfer  (note the passphrase is 'foo')

```
tpm2_create -C primary.ctx -g sha256 -G rsa -p foo -r key.prv \
-u key.pub  -L dpolicy.dat -a "sensitivedataorigin|userwithauth|decrypt|sign"
  
    [ FOR AES key use -G aes:
       tpm2_create -C primary.ctx -g sha256 -G aes -p foo -r key.prv -u key.pub  -L dpolicy.dat -a "sensitivedataorigin|userwithauth|decrypt|sign" ]

tpm2_load -C primary.ctx -r key.prv -u key.pub -c key.ctx

tpm2_readpublic -c key.ctx -o dup.pub
````

Test sign and encryption locally (so we can compare later that the same key was transferred).

```
echo "meet me at.." >file.txt
tpm2_rsaencrypt -c key.ctx  -o data.encrypted file.txt
tpm2_sign -c key.ctx -g sha256 -f plain -p foo -o sign.raw file.txt

   [ for AES key, use
     tpm2_encryptdecrypt -Q -c key.ctx -p foo -o encrypt.out secret.dat ]
```

Compare the signature hash (we will use this later to confirm the key was transferred to TPM-B):

```
sha256sum sign.raw

a1b4e3fbaa29e6e46d95cff498150b6b8e7d9fd21182622e8f5a3ddde257879e
```

Start an auth session and policy command to allow duplication
```
tpm2_startauthsession --policy-session -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
```

Load the new_parent.pub file transferred from `TPM-B`
```
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx
```

Start the duplication
```
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  \
-p "session:session.dat" -r dup.dup -s dup.seed
```

Copy the following files to TPM-B:
* dup.pub
* dup.prv
* dup.seed
* (optionally data.encrypted just to test decryption)

## On TPM-B

Start an auth,policy session
```
tpm2_startauthsession --policy-session -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
```

Load the context we used to transfer
```
tpm2_flushcontext --transient-object

tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx
```

Import the duplicated context against the parent we used
```
tpm2_import -C new_parent.ctx -u dup.pub -i dup.dup \
-r dup.prv -s dup.seed -L dpolicy.dat
```

Load the duplicated key context 
```
tpm2_flushcontext --transient-object

tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx
```

Test the imported key matches

* Sign

```bash
echo "meet me at.." >file.txt

tpm2_sign -c dup.ctx -g sha256 -o sig.rss -p foo file.txt

dd if=sig.rss of=sign.raw bs=1 skip=6 count=256
```

Compare the signature file hash:

```bash
$ sha256sum sign.raw

a1b4e3fbaa29e6e46d95cff498150b6b8e7d9fd21182622e8f5a3ddde257879e
```

* Decryption

```
tpm2_flushcontext --transient-object

tpm2_rsadecrypt -p foo -c dup.ctx -o data.ptext data.encrypted

# cat data.ptext 
meet me at..
```

## Author
@salrashid123
