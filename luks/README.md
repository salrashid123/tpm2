

## Procedure to use the TPM to do LUKS encryption

really, just see

- [https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html)



First mount the luks volume with a known passphrase

```bash
$ export luks=137d045fa3897b6fea06d8c9767b7387
$ echo  -n $luks | cryptsetup luksOpen /dev/sdb vault_encrypted_volume -
$ mount /dev/mapper/vault_encrypted_volume /mnt/disks/luks/


$ lsblk
NAME                     MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINT
sda                        8:0    0    10G  0 disk  
├─sda1                     8:1    0   9.9G  0 part  /
├─sda14                    8:14   0     4M  0 part  
└─sda15                    8:15   0   106M  0 part  /boot/efi
sdb                        8:16   0    10G  0 disk  
└─vault_encrypted_volume 253:0    0    10G  0 crypt /mnt/disks/luks

$ umount /mnt/disks/luks
$ cryptsetup luksClose   /dev/mapper/vault_encrypted_volume
```


Now seal that passphrase to the TPM at the persistent handle `0x81010001`

```bash
$ tpm2_createprimary -Q -C o -c prim.ctx
$ echo $luks | tpm2_create -Q -g sha256 -u seal.pub -r seal.priv -i- -C prim.ctx
$ tpm2_load -Q -C prim.ctx -u seal.pub -r seal.priv -n seal.name -c seal.ctx
$ tpm2_evictcontrol -C o -c seal.ctx 0x81010001


$ tpm2_unseal -Q -c 0x81010001 | xxd -p
137d045fa3897b6fea06d8c9767b7387
```

Use that tpm backed key to unseal

```bash
$ tpm2_unseal -Q -c 0x81010001 | xxd -p | cryptsetup luksOpen  /dev/sdb vault_encrypted_volume
$ mount /dev/mapper/vault_encrypted_volume /mnt/disks/luks/
```

See the link above to seal to PCR value on boot and then extend the binding PCR value (to prevent a user (root) from subsequently accessing the secret at runtime)
