package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var appleCollect bool
	flag.BoolVar(&appleCollect,
		"collect-apple",
		false,
		"Upload Apple root store file")

	var othersCollect bool
	flag.BoolVar(&othersCollect,
		"collect-others",
		false,
		"Download and upload other (Mozilla and Google) root store files")

	var windowsCollect bool
	flag.BoolVar(&windowsCollect,
		"collect-windows",
		false,
		"Upload Windows root store files")

	flag.Parse()

	log.Logger = log.Output(zerolog.NewConsoleWriter())
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	minioClient, err := misc.GetMinioClient("upload")
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting minio client")
	}

	if othersCollect {
		err = downloadAllRootStores()
		if err != nil {
			log.Fatal().Err(err).Msg("Error downloading root stores")
		}
	}

	if windowsCollect {
		err = tryExtractWindowsRootStore()
		if err != nil {
			log.Warn().Err(err).Msg("Could not extract Windows root store, continuing...")
		}
	}

	fileMap := getFileMap(appleCollect, othersCollect, windowsCollect)
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

func getFileMap(appleCollect bool, othersCollect bool, windowsCollect bool) map[string]string {
	timestamp := time.Now()
	yearMonthDay := fmt.Sprintf("year=%04d/month=%02d/day=%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())
	timestampStr := fmt.Sprintf("%04d%02d%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())

	fileMap := make(map[string]string)

	if othersCollect {
		fileMap[rootstores.TlsRootsFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.CCADBTlsS3Prefix, yearMonthDay, timestampStr, filepath.Base(rootstores.TlsRootsFile))
		fileMap[rootstores.SMimeRootsFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.CCADBSMimeS3Prefix, yearMonthDay, timestampStr, filepath.Base(rootstores.SMimeRootsFile))
		fileMap[rootstores.GoogleServicesFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.GoogleServicesS3RootStorePrefix, yearMonthDay, timestampStr, filepath.Base(rootstores.GoogleServicesFile))
		// skip microsoft code signing root store
		if false {
			fileMap[rootstores.MicrosoftCodeSigningFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.MicrosoftS3CodeSigningPrefix, yearMonthDay, timestampStr, filepath.Base(rootstores.MicrosoftCodeSigningFile))
		}
	}

	if appleCollect {
		_, err := os.Stat(rootstores.AppleRootStoreFile)
		if err == nil {
			fileMap[rootstores.AppleRootStoreFile] = fmt.Sprintf("%s/%s/%s_%s", rootstores.AppleS3RootStorePrefix, yearMonthDay, timestampStr, filepath.Base(rootstores.AppleRootStoreFile))
		} else {
			log.Warn().Err(err).Msg("Could not get Apple root store file, continuing...")
		}
	}

	if windowsCollect {
		err := tryWindowsFileMap(&fileMap, yearMonthDay)
		if err != nil {
			log.Warn().Err(err).Msg("Could not get Windows root store files, continuing...")
		}
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
