package prepare

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog/log"
	"time"
)

func RetrieveAllRootStores(scanDate time.Time) error {
	minioClient, err := misc.GetMinioClient("download")
	if err != nil {
		log.Error().Err(err).Msg("Could not get minio client")
		return err
	}

	err = misc.DownloadS3(minioClient, rootstores.GoogleServicesS3RootStorePrefix, scanDate, "shared_dir/")
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading Google Services root store")
	}

	err = misc.DownloadS3(minioClient, rootstores.CCADBTlsS3Prefix, scanDate, "shared_dir/")
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading CCADB TLS root store")
	}

	err = misc.DownloadS3(minioClient, rootstores.CCADBSMimeS3Prefix, scanDate, "shared_dir/")
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading CCADB s/MIME root store")
	}

	err = misc.DownloadS3(minioClient, rootstores.AppleS3RootStorePrefix, scanDate, "shared_dir/")
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading Apple root store")
	}

	err = misc.DownloadS3Files(minioClient, rootstores.WindowsS3Prefix, scanDate, rootstores.WindowsRootStoreDir)
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading Windows root store")
	}

	err = misc.DownloadS3Files(minioClient, rootstores.JavaS3Prefix, scanDate, rootstores.JavaRootStoreDir)
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading Java root store")
	}

	err = misc.DownloadS3Files(minioClient, rootstores.UbuntuS3Prefix, scanDate, rootstores.UbuntuRootStoreDir)
	if err != nil {
		log.Warn().Err(err).Msg("Error downloading Ubuntu root store")
	}
	return nil
}
