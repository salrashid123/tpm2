
# TPM EventLog

>>>> update 8/22:

* [https://gist.github.com/salrashid123/0c7a4a6f7465cff19d05ac50d238cd57](https://gist.github.com/salrashid123/0c7a4a6f7465cff19d05ac50d238cd57)


Generates and verifies the Event log

NOTE, pleas read:

- [https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md#event-type-and-verification-footguns](https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md#event-type-and-verification-footguns)


---

anyway, for GCE VMs, 

* debain10, sha1, with secureboot: PCR:0 `0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea`
* ubuntu21, sha256, without secureboot: PCR:0 `24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f`

- [https://github.com/google/go-tpm-tools/blob/master/server/eventlog_test.go#L226](https://github.com/google/go-tpm-tools/blob/master/server/eventlog_test.go#L226)

```
gcloud compute instances create tpm-debian \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-10-buster-v20210817 --image-project=debian-cloud --boot-disk-device-name=tpm-debian \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```


```
gcloud compute ssh tpm-debian

apt-get update
apt-get install gcc libtspi-dev wget -y


wget https://golang.org/dl/go1.17.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz
```


```log
# go run main.go   --pcr 0 --pcrValue 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea --logtostderr=1 -v 5

I0830 22:19:05.859734    7717 main.go:82] ======= Init CreateKeys ========
I0830 22:19:05.879846    7717 main.go:109] 0 handles flushed
I0830 22:19:05.881817    7717 main.go:116] PCR 0xc000016670 Value 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea 
I0830 22:19:05.881852    7717 main.go:121] ======= createPrimary ========
I0830 22:19:06.022639    7717 main.go:152] ekPub Name: 000b24516b90809f3fa0d6881b2b2da2d43710fe10ff3df765fee28288501806fae7
I0830 22:19:06.022687    7717 main.go:153] ekPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA84oNOTCWL54gk+7sJnES
hpOG+xZBQUJjvQAN1bFOJBkok9IHx/QgzxM+7UxNA47M3HIcseOQnech+4q0WnKn
LNDjfPPLdLHCUDUqi6BBAO4d8r5p+Jl7jCwAueoguKKONeTQ13vJzYfEifBZwNWk
+pBO7SmFuGHYDkWkpd6nIB1kHBniylB1o2KyF437Gbk91bC5LIkHFgO2qnURxKVL
p/iDcaUkL0+6Kl1kn5hTtoOH7YScNHiTeBmZkh5AOgTVhDxpBsX0NtPxZ/EXBGaE
DhbEA4gMQDIrwWBZCQxY0obmn0UmvRZwjikigvFgxKizYN59uTcfCuXX2Ff+cj2j
TQIDAQAB
-----END PUBLIC KEY-----
I0830 22:19:06.022707    7717 main.go:155] ======= CreateKeyUsingAuth ========
I0830 22:19:06.226766    7717 main.go:181] akPub: 0001000b00050072000000100014000b0800000000000100d140bb66c0390ed0d40842fb916a5c48dafdef88dde2418f2488f174e2fa89e2bcbeef60d661b7b1f76447c01b681203a8732284db4d84eac9917575cb807df3c9f483233fdc048b414d1e10103990a3cbd1923162372d4bf61529138b36cb11b309053e899a5f0d2aae95f3dc91b26ed696252f99c252d1efab7e72fa6b15a5ed4099bc77c303deb697b975cfb7213eddab16c528740da238529ba115c49700d7111f4672bc6cf238170a5038a58837c45553f92a5ed206b3bdf8e6ff33bc2fc36ca8174dae8a53fd3a4ed70d375c26de2dd01a9c6ba780a130ce2b5b772e0d5a4d55aea36289217b9ea436c0a431b9ee060ec709022b6202728f4fd18bc9ad,
I0830 22:19:06.226807    7717 main.go:182] akPriv: 00201bfe32bad1d2dde83f5c1cfe3352e19d33afdf93ee2744a143cbcf46b04890db0010496a85d15606f99d6392130dabc5d8b496cd62318919cc4b871d1ab8df3177c7c952d90ffe3ace62f3255514fc49c4cc375b64a6ed290b813bdd1d83d99aea9aa2e87adf8b2d15fd352f40b8072eb4169f8688d9622e3a3691eaff1168eeacc36692e9f5c375eb8fab2f77028e709ccb4ccca13e2b70f15f17d815b07a0d6bea2cf131e56472b45d7e038e742142041cea499ec3b8d051d18bd57dc417e0d7c9f78a45749a573ac07391de4f64e6d5d952d6f774390dea230354,
I0830 22:19:06.226836    7717 main.go:195] ======= LoadUsingAuth ========
I0830 22:19:06.235448    7717 main.go:223] ak keyName 0022000b5ae7d345da57c01c17272e4601767be92352aea4879648b6302c0227201f5a58
I0830 22:19:06.235898    7717 main.go:244] Event Type EV_S_CRTM_VERSION
I0830 22:19:06.235940    7717 main.go:245] PCR Index 0
I0830 22:19:06.235960    7717 main.go:246] Event Data 47004300450020005600690072007400750061006c0020004600690072006d0077006100720065002000760031000000
I0830 22:19:06.235976    7717 main.go:247] Event Digest 3f708bdbaff2006655b540360e16474c100c1310
I0830 22:19:06.235990    7717 main.go:244] Event Type EV_NONHOST_INFO
I0830 22:19:06.236006    7717 main.go:245] PCR Index 0
I0830 22:19:06.236022    7717 main.go:246] Event Data 474345204e6f6e486f7374496e666f0000000000000000000000000000000000
I0830 22:19:06.236037    7717 main.go:247] Event Digest 9e8af742718df04092551f27c117723769acfe7e
I0830 22:19:06.236050    7717 main.go:244] Event Type EV_SEPARATOR
I0830 22:19:06.236064    7717 main.go:245] PCR Index 0
I0830 22:19:06.236082    7717 main.go:246] Event Data 00000000
I0830 22:19:06.236096    7717 main.go:247] Event Digest 9069ca78e7450a285173431b3e52c5c25299e473
I0830 22:19:06.236110    7717 main.go:249] EventLog Verified
```


---


```
# tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements



version: 1
events:
  PCRIndex: 0
  EventType: EV_S_CRTM_VERSION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "3f708bdbaff2006655b540360e16474c100c1310"
  EventSize: 48
  Event: "47004300450020005600690072007400750061006c0020004600690072006d0077006100720065002000760031000000"
  PCRIndex: 0
  EventType: EV_NONHOST_INFO
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9e8af742718df04092551f27c117723769acfe7e"
  EventSize: 32
  Event: "474345204e6f6e486f7374496e666f0000000000000000000000000000000000"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "d4fdd1f14d4041494deb8fc990c45343d2277d08"
  EventSize: 53
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 10
    VariableDataLength: 1
    UnicodeName: SecureBoot
    VariableData: "01"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "5abd9412abf33e34a79b3d1a93d350e742d8ecd8"
  EventSize: 842
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 2
    VariableDataLength: 806
    UnicodeName: PK
    VariableData: "a159c0a5.."
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "f0501c79b607cc42e9142ee85a74d9c27669c0e2"
  EventSize: 1598
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 3
    VariableDataLength: 1560
    UnicodeName: KEK
    VariableData: "a159c0a5..."
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "0915a210049c2781fba26180600fb32217c7c972"
  EventSize: 3179
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 2
    VariableDataLength: 3143
    UnicodeName: db
    VariableData: "a159c0a5..."
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "5ef71a8780668451ae0612df9ba57cfb5e9ce5b4"
  EventSize: 11974
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 3
    VariableDataLength: 11936
    UnicodeName: dbx
    VariableData: "a159c0a5e494..."
  PCRIndex: 7
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 1
  EventType: EV_EFI_VARIABLE_BOOT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "a33f5b5fd6b1caddf4a4adee107a3cc91d2d14d2"
  EventSize: 54
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 9
    VariableDataLength: 4
    UnicodeName: BootOrder
    VariableData: "00000100"
  PCRIndex: 1
  EventType: EV_EFI_VARIABLE_BOOT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "22a4f6ee9af6dba01d3528deb64b74b582fc182b"
  EventSize: 110
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 8
    VariableDataLength: 62
    UnicodeName: Boot0000
    VariableData: "090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400"
  PCRIndex: 1
  EventType: EV_EFI_VARIABLE_BOOT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "1deddbe8c4412b10f998870099d4067be3da37f4"
  EventSize: 156
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 8
    VariableDataLength: 108
    UnicodeName: Boot0001
    VariableData: "010000001e005500450046004900200047006f006f0067006c0065002000500065007200730069007300740065006e0074004400690073006b002000000002010c00d041030a0000000001010600000303020800010000007fff04004eac0881119f594d850ee21a522c59b2"
  PCRIndex: 4
  EventType: EV_EFI_ACTION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "cd0fdb4531a6ec41be2753ba042637d6e5f7f256"
  EventSize: 40
  Event: |-
    Calling EFI Application from Boot Option
  PCRIndex: 0
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 1
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 2
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 3
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 4
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 5
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 6
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "0c0f8c56e09277accd603aa3cb961a2b4b81595c"
  EventSize: 1608
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 2
    VariableDataLength: 1572
    UnicodeName: db
    VariableData: "d2fa81d28..."
  PCRIndex: 5
  EventType: EV_EFI_GPT_EVENT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "b50b5c2f83e3f2d53e02b951031e30ed5e40cbe1"
  EventSize: 484
  Event: "45464..."
  PCRIndex: 4
  EventType: EV_EFI_BOOT_SERVICES_APPLICATION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "7ba9afb9a7673220a650cca9ebb0aeff683f281c"
  EventSize: 152
  Event:
    ImageLocationInMemory: 0xbd5b0018
    ImageLengthInMemory: 930016
    ImageLinkTimeAddress: 0x0
    LengthOfDevicePath: 120
    DevicePath: '02010c00d041030a00000000010106000003030208000100000004012a000f000000002000000000000000e00300000000007eeeec490d464a00b56de902f1aebb9e0202040430005c004500460049005c0042004f004f0054005c0042004f004f0054005800360034002e0045004600490000007fff0400'
  PCRIndex: 14
  EventType: EV_IPL
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "28a3343cce7732bfd9a36a2f56e780ddfe3736b1"
  EventSize: 8
  Event:
    String: |-
      MokList
  PCRIndex: 14
  EventType: EV_IPL
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "0e04412755c9737e3f66b09cb62a0afe96105882"
  EventSize: 9
  Event:
    String: |-
      MokListX
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "15875d39b8872f8aff3a92fc9f9e40ac75268e04"
  EventSize: 68
  Event:
    VariableName: 605dab50-e046-4300-abb6-3dd810dd8b23
    UnicodeNameLength: 9
    VariableDataLength: 18
    UnicodeName: SbatLevel
    VariableData: "736261742c312c323032313033303231380a"
  PCRIndex: 4
  EventType: EV_EFI_BOOT_SERVICES_APPLICATION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "3fae23b18d72350207661af3875f2c492e97621c"
  EventSize: 84
  Event:
    ImageLocationInMemory: 0xbd360018
    ImageLengthInMemory: 1549696
    ImageLinkTimeAddress: 0x0
    LengthOfDevicePath: 52
    DevicePath: '040430005c004500460049005c0042004f004f0054005c0067007200750062007800360034002e0065006600690000007fff0400'
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "2b136a029d25afc5efc9d6ac0d846fd5ca26d1d9"
  EventSize: 970
  Event:
    VariableName: 605dab50-e046-4300-abb6-3dd810dd8b23
    UnicodeNameLength: 4
    VariableDataLength: 930
    UnicodeName: Shim
    VariableData: "3082039e3082028..."
pcrs:
  sha1:
    0  : 0x0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea
    1  : 0xb1676439cac1531683990fefe2218a43239d6fe8
    2  : 0xb2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    3  : 0xb2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    4  : 0xb158404e279ecc61206b8625297c88c5ed9012b9
    5  : 0x15d9fbbc4be52d0f9653ea7e7105352aee7d02f1
    6  : 0xb2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    7  : 0xacfd7eaccc8f855aa27b2c05b8b1c7c982bfbbfa
    14 : 0x7c067190e738329a729aebd84709a7063de9219c
```