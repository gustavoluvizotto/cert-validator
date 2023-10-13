package rootstores

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"strings"
)

const (
	MicrosoftUrl  = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedRootsPEMCSVForMSFT?MicrosoftEKUs=Code%20Signing"
	MicrosoftFile = "shared_dir/IncludedRootsPEMForMSFT.csv"
)

func LoadMicrosoftRoot() ([]string, error) {
	err := Download(MicrosoftUrl, MicrosoftFile)
	if err != nil {
		return nil, err
	}

	records, err := misc.LoadCsv(MicrosoftFile)
	if err != nil {
		return nil, err
	}

	var rootStores []string
	for _, record := range records {
		pemCert := strings.ReplaceAll(record[0], "'", "")
		rootStores = append(rootStores, pemCert)
	}

	return rootStores, nil
}
