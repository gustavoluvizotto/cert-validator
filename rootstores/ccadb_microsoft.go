package rootstores

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"strings"
)

const (
	MicrosofCodeSigningtUrl      = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedRootsPEMCSVForMSFT?MicrosoftEKUs=Code%20Signing"
	MicrosoftCodeSigningFile     = "shared_dir/IncludedRootsPEMForMSFT.csv"
	MicrosoftS3CodeSigningPrefix = "rootstores/format=raw/store=microsoft-code-signing"
	WindowsRootStoreFile         = "shared_dir/windows-rootstore.zip"
	WindowsRootStoreDir          = "shared_dir/windows-rootstore"
	WindowsS3Prefix              = "rootstores/format=raw/store=microsoft-windows"
)

func LoadMicrosoftCodeSigningRoot() ([]string, error) {
	timestampFile, err := misc.GetFile(MicrosoftCodeSigningFile)
	if err != nil {
		return nil, err
	}
	records, err := misc.LoadCsv(timestampFile)
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
