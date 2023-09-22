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

const tlsUrl = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites"
const sMimeUrl = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustSMIMEPEMCSV?TrustBitsInclude=Email"
const tlsRootsFile = "IncludedRootsDistrustTLSSSLPEM.csv"
const smimeRootsFile = "IncludedRootsDistrustSMIMEPEM.csv"

const (
	TLS uint = iota
	SMIME
)

func LoadTlsRoots(rootType uint) ([]string, error) {
	var url string
	var filePath string
	if rootType == TLS {
		url = tlsUrl
		filePath = tlsRootsFile
	} else {
		url = sMimeUrl
		filePath = smimeRootsFile
	}
	err := download(url, filePath)
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

	err = os.Remove(filePath)
	if err != nil {
		log.Info().Err(err).Msg("Error removing file")
	}

	return rootStores, nil
}

func download(url string, filePath string) error {
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
