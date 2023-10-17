package main

import (
	"errors"
	"fmt"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	err := tryExtractWindowsRootStore()
	if err != nil {
		log.Warn().Err(err).Msg("Could not extract Windows root store, continuing...")
	}

	err = downloadAllRootStores()
	if err != nil {
		log.Fatal().Err(err).Msg("Error downloading root stores")
	}
	minioClient, err := misc.GetMinioClient("upload")
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting minio client")
	}
	fileMap := getFileMap()
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting upload files")
	}
	for localFile, remoteFile := range fileMap {
		err = misc.UploadS3(minioClient, localFile, remoteFile)
		if err != nil {
			log.Warn().Err(err).Str("file", localFile).Msg("Could not upload file...")
		}
		//else {
		//err = os.Remove(localFile)
		//if err != nil {
		//	log.Warn().Err(err).Msg("Could not remove local file.")
		//}
		//}
	}
	//tryCleanWindowsLocalFiles()
}

func tryExtractWindowsRootStore() error {
	_, err := os.Stat(rootstores.WindowsRootStoreFile)
	if err != nil {
		return err
	}

	err = misc.ExtractZip(rootstores.WindowsRootStoreFile, ".crt")
	if err != nil {
		return err
	}
	return nil
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

	err := tryWindowsFileMap(&fileMap, yearMonthDay)
	if err != nil {
		log.Warn().Err(err).Msg("Could not get Windows file map, continuing...")
	}

	return fileMap
}

func tryWindowsFileMap(fileMap *map[string]string, yearMonthDay string) error {
	if fileMap == nil {
		return errors.New("fileMap is nil")
	}

	_, err := os.Stat(rootstores.WindowsRootStoreDir)
	if err != nil {
		return err
	}

	certs, err := os.ReadDir(rootstores.WindowsRootStoreDir)
	if err != nil {
		return err
	}

	for _, cert := range certs {
		localFile := filepath.Join(rootstores.WindowsRootStoreDir, cert.Name())
		(*fileMap)[localFile] = fmt.Sprintf("%s/%s/%s", rootstores.WindowsS3Prefix, yearMonthDay, filepath.Base(cert.Name()))
	}
	return nil
}

func getWindowsExtractedDir() string {
	return filepath.Join(filepath.Dir(rootstores.WindowsRootStoreFile), strings.TrimSuffix(filepath.Base(rootstores.WindowsRootStoreFile), filepath.Ext(rootstores.WindowsRootStoreFile)))
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

func tryCleanWindowsLocalFiles() {
	err := os.RemoveAll(rootstores.WindowsRootStoreDir)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove Windows root store directory, continuing...")
	}
	err = os.RemoveAll(rootstores.WindowsRootStoreFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove Windows root store file, continuing...")
	}
}
