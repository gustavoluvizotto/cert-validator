package prepare

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog/log"
	"time"
)

func RetrieveAllRootStores(noApple bool, scanDate time.Time) error {
	minioClient, err := misc.GetMinioClient("download")
	if err != nil {
		log.Error().Err(err).Msg("Could not get minio client")
		return err
	}
	err = misc.DownloadS3(minioClient, rootstores.GoogleServicesS3RootStorePrefix, scanDate, "shared_dir/")
	if err != nil {
		return err
	}
	err = misc.DownloadS3(minioClient, rootstores.CCADBTlsS3Prefix, scanDate, "shared_dir/")
	if err != nil {
		return err
	}
	err = misc.DownloadS3(minioClient, rootstores.CCADBSMimeS3Prefix, scanDate, "shared_dir/")
	if err != nil {
		return err
	}
	if !noApple {
		err = misc.DownloadS3(minioClient, rootstores.AppleS3RootStorePrefix, scanDate, "shared_dir/")
		if err != nil {
			return err
		}
	}
	return nil
}
