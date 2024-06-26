module main

go 1.22

toolchain go1.22.2

require (
	github.com/google/go-tpm v0.9.1-0.20240411180339-1fb84445f623
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba
)

require (
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.15.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

// replace (
// 	github.com/google/go-tpm  => "./go-tpm"
// )