package rootstores

import (
	"context"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	endpoint                 = "localhost:8080"
	bucket                   = "catrin"
	AppleS3RootStoreLocation = "rootstores/format=raw/store=apple/"
)

var AppleRootStoreFile = "shared_dir/" // + filename to be filled in DownloadAppleRootStore if no error

func DownloadAppleRootStore(scanDate time.Time) error {
	cred := credentials.NewFileAWSCredentials("credentials", "download")

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  cred,
		Secure: false,
	})

	if err != nil {
		return err
	}

	var appleRootStoreS3File string
	listOpts := minio.ListObjectsOptions{
		Prefix:    AppleS3RootStoreLocation,
		Recursive: true,
	}
	ctx := context.Background()
	for obj := range minioClient.ListObjects(ctx, bucket, listOpts) {
		if obj.Err != nil {
			return obj.Err
		}
		timestamp, err := time.Parse("20060102", strings.Split(filepath.Base(obj.Key), "_")[0])
		if err != nil {
			return err
		}
		if timestamp.Before(scanDate) {
			appleRootStoreS3File = obj.Key
			break
		}
	}

	obj, err := minioClient.GetObject(ctx, bucket, appleRootStoreS3File, minio.GetObjectOptions{Checksum: true})
	if err != nil {
		return err
	}
	defer func(obj *minio.Object) {
		err := obj.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing object.")
		}
	}(obj)

	AppleRootStoreFile += filepath.Base(appleRootStoreS3File)
	localFile, err := os.Create(AppleRootStoreFile)
	if err != nil {
		return err
	}
	defer func(localFile *os.File) {
		err := localFile.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing file.")
		}
	}(localFile)

	if _, err = io.Copy(localFile, obj); err != nil {
		return err
	}

	return nil
}
