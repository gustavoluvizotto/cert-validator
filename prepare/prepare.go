package prepare

import (
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog/log"
	"time"
)

func DownloadAllRootStores(noApple bool, scanDate time.Time) error {
	err := rootstores.Download(rootstores.TlsUrl, rootstores.TlsRootsFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading CCADB TLS root certificates")
		return err
	}
	err = rootstores.Download(rootstores.SMimeUrl, rootstores.SMimeRootsFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading CCADB sMIME root certificates")
		return err
	}
	err = rootstores.Download(rootstores.MicrosoftUrl, rootstores.MicrosoftFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Warning! Could not load Microsoft root certificates")
		return err
	}
	err = rootstores.Download(rootstores.GoogleServicesURL, rootstores.GoogleServicesFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Warning! Could not download Google services root certificates")
		return err
	}
	if !noApple {
		err = rootstores.DownloadAppleRootStore(scanDate)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not download Apple root certificates")
			return err
		}
	}
	return nil
}
