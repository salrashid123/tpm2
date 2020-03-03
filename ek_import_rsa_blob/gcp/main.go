package main

import (
	"context"
	"flag"
	"log"

	"github.com/golang/glog"
	sal "github.com/salrashid123/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/google/go-tpm/tpm2"
)

const defaultRSAExponent = 1<<16 + 1

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	mode                = flag.String("mode", "", "pubsub or gcs")
	tpmPath             = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	keyHandleFile       = flag.String("keyHandleFile", "key.bin", "Path to the KeyHandle blob).")
	serviceAccountEmail = flag.String("serviceAccountEmail", "", "Email for the serviceAccount (required)")
	keyId               = flag.String("keyId", "", "private KeyID for the serviceAccount")
	projectId           = flag.String("projectId", "", "ProjectID")
)

func main() {
	flag.Parse()

	if *serviceAccountEmail == "" || *keyId == "" || *projectId == "" {
		glog.Fatalln("You must specify --serviceAccountEmail, --keyId --projectId")
	}

	switch *mode {
	case "pubsub":
		if *keyHandleFile == "" {
			glog.Fatalf("keyHandleFile must be set when using: %v", *mode)
		}
		err := testpubsub()
		if err != nil {
			glog.Fatalf("Error createSigningKeyImportBlob: %v\n", err)
		}
	case "gcs":
		if *keyHandleFile == "" {
			glog.Fatalf("keyHandleFile must be set when using: %v", *mode)
		}
		err := testgcs()
		if err != nil {
			glog.Fatalf("Error createSigningKeyImportBlob: %v\n", err)
		}
	default:
		glog.Fatalf("mode must be either pubsub or gcs")

	}

}

func testpubsub() (retErr error) {

	glog.V(2).Infof("======= Listing PubSub Topics ========")

	ts, err := sal.TpmTokenSource(
		&sal.TpmTokenConfig{
			Tpm:           *tpmPath,
			Email:         *serviceAccountEmail,
			KeyHandleFile: *keyHandleFile,
			Audience:      "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
			KeyId:         *keyId,
		},
	)
	if err != nil {
		glog.Fatal(err)
	}

	ctx := context.Background()
	pubsubClient, err := pubsub.NewClient(ctx, *projectId, option.WithTokenSource(ts))
	if err != nil {
		glog.Fatalf("Could not create pubsub Client: %v", err)
	}
	it := pubsubClient.Topics(ctx)
	for {
		topic, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			glog.Fatalf("Unable to iterate topics %v", err)
		}
		glog.V(2).Infof("Topic: %s", topic.ID())
	}

	return nil

}

func testgcs() (retErr error) {

	glog.V(2).Infof("======= Listing PubSub Topics ========")

	ts, err := sal.TpmTokenSource(
		&sal.TpmTokenConfig{
			Tpm:           *tpmPath,
			Email:         *serviceAccountEmail,
			KeyHandleFile: *keyHandleFile,
			KeyId:         *keyId,
			UseOauthToken: true,
		},
	)
	if err != nil {
		glog.Fatal(err)
	}
	// GCS does not support JWTAccessTokens, the following will only work if UseOauthToken is set to True
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		glog.Fatal(err)
	}
	sit := storageClient.Buckets(ctx, *projectId)
	for {
		battrs, err := sit.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		glog.V(2).Infof(battrs.Name)
	}

	return nil

}
