package main

import (
	"fmt"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	err := downloadAllRootStores()
	if err != nil {
		log.Fatal().Err(err).Msg("Error downloading root stores")
	}
	minioClient, err := misc.GetMinioClient("upload")
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting minio client")
	}
	fileMap := getFileMap()
	if err != nil {
		log.Error().Err(err).Msg("Error getting upload files")
		return
	}
	for localFile, remoteFile := range fileMap {
		err = misc.UploadS3(minioClient, localFile, remoteFile)
		if err != nil {
			log.Error().Err(err).Str("file", localFile).Msg("Error uploading file, try again...")
		} else {
			err = os.Remove(localFile)
			if err != nil {
				log.Warn().Err(err).Msg("Could not remove file.")
			}
		}
	}
}

func getFileMap() map[string]string {
	timestamp := time.Now()
	yearMonthDay := fmt.Sprintf("year=%04d/month=%02d/day=%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())
	timestampStr := fmt.Sprintf("%04d%02d%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())

	fileMap := make(map[string]string)
	fileMap[rootstores.TlsRootsFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.CCADBTlsS3Prefix, yearMonthDay, timestampStr, filepath.Base(rootstores.TlsRootsFile))
	fileMap[rootstores.SMimeRootsFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.CCADBSMimeS3Prefix, yearMonthDay, timestampStr, filepath.Base(rootstores.SMimeRootsFile))
	fileMap[rootstores.GoogleServicesFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.GoogleServicesS3RootStorePrefix, yearMonthDay, timestampStr, filepath.Base(rootstores.GoogleServicesFile))
	// skip microsoft code signing root store
	if false {
		fileMap[rootstores.MicrosoftCodeSigningFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.MicrosoftS3CodeSigningPrefix, yearMonthDay, timestampStr, filepath.Base(rootstores.MicrosoftCodeSigningFile))
	}

	return fileMap
}

func downloadAllRootStores() error {
	err := misc.Download(rootstores.TlsUrl, rootstores.TlsRootsFile)
	if err != nil {
		log.Error().Err(err).Msg("Error loading CCADBTLSTYPE root certificates")
		return err
	}
	err = misc.Download(rootstores.SMimeUrl, rootstores.SMimeRootsFile)
	if err != nil {
		log.Error().Err(err).Msg("Error loading CCADB sMIME root certificates")
		return err
	}
	if false {
		// not required
		err = misc.Download(rootstores.MicrosofCodeSigningtUrl, rootstores.MicrosoftCodeSigningFile)
		if err != nil {
			log.Error().Err(err).Msg("Could not load Microsoft code signing root certificates")
			return err
		}
	}
	err = misc.Download(rootstores.GoogleServicesURL, rootstores.GoogleServicesFile)
	if err != nil {
		log.Error().Err(err).Msg("Could not download Google services root certificates")
		return err
	}
	return nil
}
