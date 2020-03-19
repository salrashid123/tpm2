

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

So  first set a binding PCR value as root (uid=0)

```bash
root@shielded-1:~# tpm2_pcrread sha256:23
sha256:
  23: 0xC52B960075A08DCEC51678896BE3EC4761FBC2FEBEB0C325E21E30AEC560246F
root@shielded-1:~# exit
logout
```

Then as uid=1001, simply type data and check the PCR value:

```
srashid@shielded-1:~$ date
Fri Dec 27 02:01:27 UTC 2019

srashid@shielded-1:~$ sudo su -

root@shielded-1:~# tpm2_pcrread sha256:23
sha256:
  23: 0x741340FA5E38B91AD202C67B8C801B65BEC7A36F19EF033CDC4C820A9F79637C
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


$ vi /etc/default/grub
  GRUB_CMDLINE_LINUX="ima_policy=tcb" 

$ sudo update-grub 

# more /etc/initramfs-tools/scripts/init-top/ima_policy
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
```

---
