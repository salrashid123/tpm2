### EK-Based Key Attestation with TPM Firmware Version


Simple demo of [EK-Based Key Attestation with TPM Firmware Version](https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-Version-1_Pub.pdf)


![images/ek_attestation.png](images/ek_attestation.png)


```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"


$ go run main.go 

2026/04/17 10:28:07 ======= create ekPublic on Attestor  ========
2026/04/17 10:28:07 Name 000b3f0a4250b207f11b4362c6db35ce02c6ceba71cc4013117fcab121ee98f202b6
2026/04/17 10:28:07 RSA EK createPrimary public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlApbI0PRwxG3/g2nOXkM
pt9Rk5b1+PaJYrpsQsdVd+At9anP0LiEuq3Nyf0E1MIvbYxPrRQFzo+OWeeL3Aqm
VB61zKzgfKmknIyBDS2S29hOVXjQyPu2mCkSZQ2Pti/0e8JlpVNjZd0YnGqpfvaU
F28bMDmko4a58KjGqdBt2Z9Djne4CdPHjro+9StW4m4fMy/zETWHzPSqH9Rse2y1
iL+7ve7sLtXbN3ff10SMjw45+Lkyfwa1r+D2hMDTgHpcvFCGWau9pZIFHVenBEbE
QV7xfXQd4aMaClWyqPkRRwseV0QxRQltbplTdz28Wb8FfmCR8Eh0F+jnuK5vy8GE
0QIDAQAB
-----END PUBLIC KEY-----

2026/04/17 10:28:07 ======= send the ekPub.PEM to the Verifier ========
2026/04/17 10:28:07 ======= create a random HMAC key and duplicate it ========
duplicateTemplate Name 000b46bd301af69ae8d0a23657d3716e2e9065817d19c7cca9ca3a216b1666a619cc
2026/04/17 10:28:07 ======= verifier sends duplicate key, duplicate seed and duplicate pub to Attestor ========
2026/04/17 10:28:07 ======= Attestor creates  EK ========
2026/04/17 10:28:07 ======= Attestor imports the duplicated hmac key ========
2026/04/17 10:28:07 ======= Attestor creates AK ========
2026/04/17 10:28:07 Created AK Name :000b2d7732b0f4eac16a730fad18c247a62ac940b8afebad88493f01192d26de6b86
2026/04/17 10:28:07 AK RSA Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs85JVjtTDGRMgBbw3fLL
4KiS1zgfHdY2jsJihdHjdPEydUEhsx3AMUouJyKmq+o1gvw8ra4TBkZCDk51WUvl
XJugki5jyNCig699BLfMOLvGwo5wy+avHDegPYzVpGJ81H4jx4ObElHiJtKbG2Yx
mB8YWn2RfimHladjjuvWD4w4AZoPFF00z7WFqx3TlQADjR3ZjIX7BH+8pEXWuPC0
mEO7n43iO/KsDeqy8kxslSQiw6GIJw0jA2NdKH3Sj+iH4cSJPaNwAKqXuKWW/Azi
yz7Qj/Ul6pC6ygMOXI9vY+LTpJfAARnJ9he4CDROb4hVUhO/F8eqmxYYhasSWyeo
RQIDAQAB
-----END PUBLIC KEY-----

2026/04/17 10:28:07 ======= Attestor certifies ak with the duplicated key ========
2026/04/17 10:28:07 ======= Attestor sends attestation signature,attestation and the AK RSA Public key (akPubPEM) to Verifier ========
2026/04/17 10:28:07 Certify Response digest M4qEUUdA2ny8SoZqoTvhEVSQCAHFQiArOzuaIVWjtnA=
2026/04/17 10:28:07 ======= verifier checks attesatation certification info specifications ========
2026/04/17 10:28:07 Certify Firmware Version 2315977366801874944
2026/04/17 10:28:07 Certify AK Name 000b2d7732b0f4eac16a730fad18c247a62ac940b8afebad88493f01192d26de6b86
2026/04/17 10:28:07 Certify Extra Data 
2026/04/17 10:28:07 Derived Name from rsa PublicKey 000b2d7732b0f4eac16a730fad18c247a62ac940b8afebad88493f01192d26de6b86
2026/04/17 10:28:07 Attesation names match
2026/04/17 10:28:07 ======= Attestor verifies the HMAC signature of the attesation certification info  ========
2026/04/17 10:28:07 calculated hmac of attestation using local hmac key M4qEUUdA2ny8SoZqoTvhEVSQCAHFQiArOzuaIVWjtnA=
2026/04/17 10:28:07 attestation verified

```
