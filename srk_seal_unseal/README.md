# SEAL DATA TO TPM using PCR value at back 23



- Define policy file:
```bash
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_createpolicy --policy-pcr -l sha256:23 -L policy.file -f pcr23_val.bin

echo "foo" > secret.dat

# optionally seed the "unique" bit
# https://github.com/tpm2-software/tpm2-tools/issues/2378
printf '\x00\x01' > ud.1
dd if=/dev/random bs=256 count=1 of=ud.2
cat ud.1 ud.2 > unique.dat

tpm2_createprimary -C o -c primary.ctx -u unique.dat
echo "my sealed data" > seal.dat
tpm2_create -C primary.ctx -i seal.dat -u key.pub -r key.priv -L policy.file 
tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx

tpm2_unseal -o unseal.dat -c key.ctx -p"pcr:sha256:23=pcr23_val.bin"

cat unseal.dat 
```

otherwise, with a pcrextend, you can't unseal

```
$ tpm2_pcrextend 23:sha256=0xC78009FDF07FC56A11F122370658A353AAA542ED63E44C4BC15FF4CD105AB33C
$ tpm2_pcrread sha256:23
    sha256:
      23: 0x536D98837F2DD165A55D5EEAE91485954472D56F246DF256BF3CAE19352A123C
```

```bash
tpm2_unseal -o unseal.dat -c key.ctx -p"pcr:sha256:23=pcr23_val.bin"
WARNING:esys:src/tss2-esys/api/Esys_Unseal.c:291:Esys_Unseal_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Unseal.c:98:Esys_Unseal() Esys Finish ErrorCode (0x0000099d) 
ERROR: Esys_Unseal(0x99D) - tpm:session(1):a policy check failed
ERROR: Unable to run tpm2_unseal
```

---

```
# go run main.go --pcr 23
// 2019/10/28 23:27:08 Handle 0x2000000 flushed
// 2019/10/28 23:27:08 Handle 0x2000001 flushed
// 2019/10/28 23:27:08 2 handles flushed
// 2019/10/28 23:27:08 Loaded SRK: {<nil> 0xc00000ea60}
// 2019/10/28 23:27:08 PCR [23] handle: 23
// 2019/10/28 23:27:08 Key material sealed on file [0xc00004a720] with PCR: 23
```