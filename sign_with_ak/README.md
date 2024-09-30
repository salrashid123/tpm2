
# TPM Sign with AK

```bash
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -n ak.name -u ak.pub

tpm2_readpublic -c ek.ctx -o ek.pem -f PEM

cat ek.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7U6d8qx3jNYczU/YUOwg
yWgSQSvRRiTV5963lfUFTkbLfmbxCbsjysVMpJTDseO6JTnN7ogmRL8AjgKe3swH
k6sfM1/pVnTLRb6fGANU043y8J3dUyRg6n3b2mUfbfCcH7fWwVMIk6ZpzwQ5l4Ib
wD7g5EWZDTVkyPNC12MZFFozk506gPQJWXzzM7N+Dq0tjkKhBkygewiKh+nY8wmg
bR31x3/kp8sStqLEbWgstpZKEq20AJux/NFdwqXtSRmwbiVDqwIsn5qrmECNW0OZ
35WYmGVajAOcdlXcWUzeyh4l47ut9GbYsnAX8kkxpfQ4fTHHwmhNSfS4TwQwDBSM
+wIDAQAB
-----END PUBLIC KEY-----


echo "meet me at.." > message.txt

tpm2_hash -C e -g sha256 -o hash.bin -t ticket.bin message.txt

## w/o ticket
tpm2_sign -c ak.ctx -g sha256 -o sig.rssa message.txt
  ERROR: Eys_Sign(0x3E0) - tpm:parameter(3):invalid ticket
  ERROR: Unable to run tpm2_sign

## w/ ticket

tpm2_sign -c ak.ctx -g sha256 -o sig.rssa -t ticket.bin message.txt

tpm2_verifysignature -c ak.ctx -g sha256 -s sig.rssa -m message.txt
```


```bash
$ go run main.go 

2024/09/30 11:35:43 ======= Init  ========
2024/09/30 11:35:43 ======= EK ========
2024/09/30 11:35:43 Name 000b9a04eaa73cc7ed6556b8874ea2eade41b9f564b024ef98782065192542e1fc33
2024/09/30 11:35:43 RSA createPrimary public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7U6d8qx3jNYczU/YUOwg
yWgSQSvRRiTV5963lfUFTkbLfmbxCbsjysVMpJTDseO6JTnN7ogmRL8AjgKe3swH
k6sfM1/pVnTLRb6fGANU043y8J3dUyRg6n3b2mUfbfCcH7fWwVMIk6ZpzwQ5l4Ib
wD7g5EWZDTVkyPNC12MZFFozk506gPQJWXzzM7N+Dq0tjkKhBkygewiKh+nY8wmg
bR31x3/kp8sStqLEbWgstpZKEq20AJux/NFdwqXtSRmwbiVDqwIsn5qrmECNW0OZ
35WYmGVajAOcdlXcWUzeyh4l47ut9GbYsnAX8kkxpfQ4fTHHwmhNSfS4TwQwDBSM
+wIDAQAB
-----END PUBLIC KEY-----

2024/09/30 11:35:44 RSA Attestation Key 
-----BEGIN PUBLIC KEY-----
spFymZ7eHkFcEoRzYnM7Jx85w0VXsmt8Mjun3p2q+S5C38VgrUB2Ll3FryvMfjEW
WLEmcltzj7vq23afkLFArkWFVATSOZclOpDUzPXgk33T6+qYhgkYY3GgoQ3zk+pu
5F3sUZZgEUwbe/26yt9Zj8d3V7KKJ/PcjH3La+TlhhEzT6S2igrZuBWI9sRU8fWG
/uYPMgJSVkAHPJVOTamnENXClZwDkZCgfZov2moQsb31XBNfIWNm5GzQqbzrSG4G
61JzYdtXIj4xzJ14u/eFYouEk0pRvVmw21CcfZUFjb8svrJRr9z0jbNeXqPff16R
xrKqANCWoQDOen471LGRZw==
-----END PUBLIC KEY-----

2024/09/30 11:35:44 ======= generate test signature with RSA key ========
2024/09/30 11:35:44 signature: Y/nrXl18MCJ8SIcbilJKt9Ioe/tsQLrqQSYj4YL+doNrGUiRBB4ACtEQ5gpa4IJIBm6/Z+tb4MDL/NJiCEFD6I7XHgzgIj6RZ6KN9nGtyjcTT64m6Rb0FXjBBP3mGVtzRIc0Uy1/DFi67JyfNmaVxTbjpz1UZnwuEjEAGzONXuV7n5rP/OpSXriHIsvja5GCwKVigHprcWz2i68gDoxHKnGbPojAx2tgT7vKwtAndLQvc7o//Hv5yB/Kn7PwY9bOhSS2Ubpdkr8yvXF7CtvSokNuuzThwy6vu7d0r32l9QDh1cVRhYjxEq5kB936tJlR9n5maRLIgvkB5TKwz5htQA==

```