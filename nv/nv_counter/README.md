### TPM NV Policy with counter (tpm2_nvincrement and tpm2_policynv)


The following creates an NV entry which can be incremented `tpm2_nvincrement` 

THen a `tpm2_policynv` is used to limit unsealing of an object only if the nv value is 2.

(meaning you can limit the number of times an tpm seal/sign/encrypt operation occurs)
ures-01.38.pdf

```bash

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"

##  define counter of 2 at nv
tpm2_nvdefine -C o -s 8 -a "ownerread|authread|authwrite|nt=1" 0x01000000 -p index
tpm2_nvincrement -C 0x01000000  0x01000000 -P "index"
tpm2_nvincrement -C 0x01000000  0x01000000 -P "index"
tpm2_nvread 0x01000000 -P index | xxd -p

### create parent
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat


## create key with policy nv where nv must be 2 (or rather 0000000000000002 offset 0)
tpm2_startauthsession -S session.ctx --policy-session
echo "0000000000000002" | xxd -r -p | tpm2_policynv -S session.ctx -L policy.digest -i- 0x01000000 eq -C o  --offset 0
tpm2_flushcontext session.ctx
tpm2_flushcontext -t

### create object with that policy and seal data
echo "my sealed data" > seal.dat
tpm2_create -C primary.ctx -i seal.dat -u key.pub -r key.priv -L policy.digest 
tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_flushcontext -t

### now create a session with policy nv that is active and unseal
tpm2_startauthsession -S session.ctx --policy-session
echo "0000000000000002" | xxd -r -p | tpm2_policynv -S session.ctx -L policy.digest -i- 0x01000000 eq -C o  --offset 0
tpm2_unseal -o unseal.dat -c key.ctx -p "session:session.ctx"
tpm2_flushcontext session.ctx
cat unseal.dat 
tpm2_flushcontext -t

### now increment the nv counter to make it 3
tpm2_nvincrement -C 0x01000000  0x01000000 -P "index"
tpm2_nvread 0x01000000 -P index | xxd -p

## create a policy with nv value of 2 will fail
tpm2_startauthsession -S session.ctx --policy-session
echo "0000000000000002" | xxd -r -p | tpm2_policynv -S session.ctx -L policy.digest -i- 0x01000000 eq -C o  --offset 0
tpm2_flushcontext session.ctx
tpm2_flushcontext -t

### so attempt to create a policy with nv=3  which will pass
tpm2_startauthsession -S session.ctx --policy-session
echo "0000000000000003" | xxd -r -p | tpm2_policynv -S session.ctx -L policy.digest -i- 0x01000000 eq -C o  --offset 0

### but using that doest match the policy
tpm2_unseal -o unseal.dat -c key.ctx -p "session:session.ctx"
tpm2_flushcontext session.ctx
tpm2_flushcontext -t











