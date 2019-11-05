
# TPM Sign with AK

```
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -n ak.name -u ak.pub


echo "meet me at.." > message.txt

tpm2_hash -C e -g sha256 -o hash.bin -t ticket.bin message.txt

w/o ticket
tpm2_sign -c ak.ctx -g sha256 -o sig.rssa message.txt
  ERROR: Eys_Sign(0x3E0) - tpm:parameter(3):invalid ticket
  ERROR: Unable to run tpm2_sign

w/ ticket

tpm2_sign -c ak.ctx -g sha256 -o sig.rssa -t ticket.bin message.txt

tpm2_verifysignature -c ak.ctx -g sha256 -s sig.rssa -m message.txt
```
