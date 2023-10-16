package rootstores

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"strings"
	"time"
)

const (
	TlsUrl             = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites"
	SMimeUrl           = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustSMIMEPEMCSV?TrustBitsInclude=Email"
	TlsRootsFile       = "shared_dir/IncludedRootsDistrustTLSSSLPEM.csv"
	SMimeRootsFile     = "shared_dir/IncludedRootsDistrustSMIMEPEM.csv"
	CCADBTlsS3Prefix   = "rootstores/format=raw/store=ccadb-tls"
	CCADBSMimeS3Prefix = "rootstores/format=raw/store=ccadb-smime"
)

const (
	CCADBTLSTYPE uint = iota
	CCADBSMIMETYPE
)

func LoadCCADBRoots(rootType uint) ([]string, error) {
	var filePath string
	if rootType == CCADBTLSTYPE {
		filePath = TlsRootsFile
	} else {
		filePath = SMimeRootsFile
	}
	timestampFile, err := misc.GetFile(filePath)
	if err != nil {
		return nil, err
	}
	records, err := misc.LoadCsv(timestampFile)
	if err != nil {
		return nil, err
	}

	var rootStores []string
	for _, v := range records {
		var distrustDate time.Time
		if v[1] != "" {
			distrustDate, err = time.Parse("2006.01.02", v[1])
			if err == nil && distrustDate.Before(time.Now()) {
				// skip if distrust date is in the past
				continue
			}
		}
		pemCert := strings.ReplaceAll(v[0], "'", "")
		rootStores = append(rootStores, pemCert)
	}

	return rootStores, nil
}
