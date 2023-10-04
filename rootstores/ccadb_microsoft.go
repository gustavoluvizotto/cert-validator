package rootstores

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/rs/zerolog/log"
	"os"
	"strings"
)

const (
	microsoftUrl  = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedRootsPEMCSVForMSFT?MicrosoftEKUs=Code%20Signing"
	microsoftFile = "IncludedRootsPEMForMSFT.csv"
)

func LoadMicrosoftRoot() ([]string, error) {
	err := Download(microsoftUrl, microsoftFile)
	if err != nil {
		return nil, err
	}

	records, err := misc.LoadCsv(microsoftFile)
	if err != nil {
		return nil, err
	}

	var rootStores []string
	for _, record := range records {
		pemCert := strings.ReplaceAll(record[0], "'", "")
		rootStores = append(rootStores, pemCert)
	}

	err = os.Remove(microsoftFile)
	if err != nil {
		log.Info().Err(err).Msg("Error removing file")
	}
	return rootStores, nil
}
