# Attest and Verify using go-tpm-tools


using [https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.1/server#VerifyAttestation](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.1/server#VerifyAttestation)


- `confirmGCESEV` verifies if AMD SEV is enabled on GCE instances only [https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#integrity-monitoring](https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#integrity-monitoring)

on an ordinary vm you'll see `EV SEVStatus: None`

```log
# go run main.go --confirmGCESEV=true
2023/08/09 14:32:02 Attestation Verified
2023/08/09 14:32:02 =============== Parsing EventLog ===============
2023/08/09 14:32:02      secureBoot State enabled true
2023/08/09 14:32:02      PCR and eventlogs verified, assessing SEV Status for GCE:
2023/08/09 14:32:02      EV SevStatus: NONE
```