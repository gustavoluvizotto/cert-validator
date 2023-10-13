package rootstores

import (
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	TlsUrl         = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites"
	SMimeUrl       = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustSMIMEPEMCSV?TrustBitsInclude=Email"
	TlsRootsFile   = "shared_dir/IncludedRootsDistrustTLSSSLPEM.csv"
	SMimeRootsFile = "shared_dir/IncludedRootsDistrustSMIMEPEM.csv"
)

const (
	TLS uint = iota
	SMIME
)

func LoadCCADBRoots(rootType uint) ([]string, error) {
	var url string
	var filePath string
	if rootType == TLS {
		url = TlsUrl
		filePath = TlsRootsFile
	} else {
		url = SMimeUrl
		filePath = SMimeRootsFile
	}
	err := Download(url, filePath)
	if err != nil {
		return nil, err
	}

	records, err := misc.LoadCsv(filePath)
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

func Download(url string, filePath string) error {
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		err = out.Close()
		if err != nil {
			log.Fatal().Err(err).Msg("Error closing file")
		}
	}(out)

	resp, err := http.Get(url)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal().Err(err).Msg("Error closing response body")
		}
	}(resp.Body)

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatal().Err(err).Msg("Error copying response body to file")
		return err
	}

	return nil
}
