package rootstores

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"strings"
)

const (
	MicrosofCodeSigningtUrl  = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedRootsPEMCSVForMSFT?MicrosoftEKUs=Code%20Signing"
	MicrosoftCodeSigningFile = "shared_dir/IncludedRootsPEMForMSFT.csv"
)

func LoadMicrosoftCodeSigningRoot() ([]string, error) {
	err := Download(MicrosofCodeSigningtUrl, MicrosoftCodeSigningFile)
	if err != nil {
		return nil, err
	}

	records, err := misc.LoadCsv(MicrosoftCodeSigningFile)
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
