

## IMA Policy

IMA Policy Daemon will monitor a variety of system states (eg file changes, etc).  If it detects a change, a corresponding PCR values will get updated


- [https://sourceforge.net/p/linux-ima/wiki/Home/](https://sourceforge.net/p/linux-ima/wiki/Home/)
- [https://www.kernel.org/doc/Documentation/ABI/testing/ima_policy](https://www.kernel.org/doc/Documentation/ABI/testing/ima_policy)
- [https://wiki.strongswan.org/projects/strongswan/wiki/IMA#Configure-the-IMA-Policy](https://wiki.strongswan.org/projects/strongswan/wiki/IMA#Configure-the-IMA-Policy)

### Sample PCR Update

The following shows an impractical use of an IMA configuration:  even if a user types `date` a PCR register is updated...

This IMA policy monitors filechanges done by `uid=1001` and updates `PCR:23`


```bash
measure func=BPRM_CHECK uid=1001 pcr=23
measure func=FILE_MMAP uid=1001 pcr=23
measure func=FILE_CHECK uid=1001 pcr=23
```

Login as root, check pcr23:
```
root@tpm-a:~# tpm2_pcrread sha256:23
sha256:
  23: 0x1722810108259E0E3BFE4D88D0828281958B4B2267ADDF6DD6A59267326C2BA1
```

As uid=10001 simply type `date`
```
srashid@tpm-a:~$ date
Mon Mar 23 14:48:40 UTC 2020
```

Check the pcr23 value again:
```
# tpm2_pcrread sha256:23
sha256:
  23: 0xB0AD349B20FAED608B844321D6271B127DBDD7C706FD3CB2BEEC49709605F687

cat /sys/kernel/security/ima/ascii_runtime_measurements
   23 140ecfbecee34e5061683da00a56bbd53d7461e2 ima-ng sha1:639298eff80832b052380567e1a7a31261e35509 /bin/date
```


### TPM2 seal/unseal using a PCR's value

Snippet that seals some data to a TPM for a given PCR Value:

```bash
tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

tpm2_pcrread sha256:23 -o pcr23_val.bin
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B


tpm2_createpolicy --policy-pcr -l sha256:23 -L policy.file -f pcr23_val.bin


tpm2_createprimary -C e -c primary.ctx
echo "my sealed data" > seal.dat
tpm2_create -C primary.ctx -i seal.dat -u key.pub -r key.priv -L policy.file 

tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx


tpm2_pcrextend 23:sha256=0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
tpm2_unseal -o unseal.dat -c key.ctx -p"pcr:sha256:23=pcr23_val.bin"
```

#### IMA POLICY Installation

```bash
apt install ima-evm-utils


vi /etc/default/grub
 add
   GRUB_CMDLINE_LINUX="ima_tcb ima_hash=sha256" 
sudo update-grub

$ sudo update-grub 

# vi /etc/initramfs-tools/scripts/init-top/ima_policy
#!/bin/sh

PREREQ="" 

prereqs()
{
    echo "$PREREQ" 
}

case $1 in
# get pre-requisites
prereqs)
    prereqs
    exit 0
    ;;
esac

# mount securityfs
SECURITYFSDIR="/sys/kernel/security" 
mount -t securityfs securityfs ${SECURITYFSDIR} >/dev/null 2>&1

cat << @EOF > ${SECURITYFSDIR}/ima/policy
# PROC_SUPER_MAGIC
dont_measure fsmagic=0x9fa0
# SYSFS_MAGIC
dont_measure fsmagic=0x62656572
# DEBUGFS_MAGIC
dont_measure fsmagic=0x64626720
# TMPFS_MAGIC
dont_measure fsmagic=0x01021994
# RAMFS_MAGIC
dont_measure fsmagic=0x858458f6
# SECURITYFS_MAGIC
dont_measure fsmagic=0x73636673
# MEASUREMENTS

measure func=BPRM_CHECK uid=1001 pcr=23
measure func=FILE_MMAP uid=1001 pcr=23
measure func=FILE_CHECK uid=1001 pcr=23
audit func=BPRM_CHECK  uid=1001
@EOF

```

```bash
ls /sys/kernel/security/ima
chmod a+x /etc/initramfs-tools/scripts/init-top/ima_policy
update-initramfs -u
reboot
```

---
