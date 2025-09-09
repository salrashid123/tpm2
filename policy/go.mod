module main

go 1.22.0

toolchain go1.24.0

require (
	github.com/google/go-tpm v0.9.2-0.20240920144513-364d5f2f78b9
	github.com/google/go-tpm-tools v0.4.4
)

require (
	github.com/google/go-sev-guest v0.11.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)

// replace github.com/salrashid123/tpm2genkey => ../../tpm2genkey
