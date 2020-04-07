module main

go 1.13

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/golang/protobuf v1.3.3
	github.com/google/go-tpm v0.2.1-0.20191106030929-f0607eac7f8a
	github.com/google/go-tpm-tools v0.1.3-0.20200229023135-1b9abc4c9ab8

	github.com/google/uuid v1.1.1
	github.com/hashicorp/vault/api v1.0.4 // indirect

	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/salrashid123/oauth2 v0.0.0-20200306182411-2f0ea7dcf344
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	google.golang.org/api v0.21.0 // indirect
	google.golang.org/grpc v1.28.0
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	verifier v0.0.0
)

replace verifier => ./src/verifier
