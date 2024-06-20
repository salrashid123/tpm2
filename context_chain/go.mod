module main

go 1.22

toolchain go1.22.2

// github.com/google/go-tpm v0.9.1-0.20240510201744-5c2f0887e003
require github.com/google/go-tpm-tools v0.4.4

// require github.com/salrashid123/signer/tpm v0.0.0-20240607164123-b64bf0a3f447

require github.com/google/go-tpm v0.9.0

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

// replace github.com/google/go-tpm => ./go-tpm
