package rootstores

import (
	"crypto/x509"
	"errors"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"time"
)

const (
	CCADBTLS             = "CCADBTLS"
	CCADBSMIME           = "CCADBSMIME"
	GOOGLESERVICES       = "GOOGLESERVICES"
	APPLE                = "APPLE"
	MICROSOFTWINDOWS     = "MICROSOFTWINDOWS"
	MICROSOFTCODESIGNING = "MICROSOFTCODESIGNING"
	CUSTOM               = "CUSTOM"
)

var RootCertsPool = map[string]*x509.CertPool{
	CCADBTLS:         nil,
	CCADBSMIME:       nil,
	GOOGLESERVICES:   nil,
	APPLE:            nil,
	MICROSOFTWINDOWS: nil,
	//MICROSOFTCODESIGNING: nil,
}

func IsEmptyRootCertsPool() bool {
	for _, pool := range RootCertsPool {
		if pool != nil {
			return false
		}
	}
	return true
}

func PoolRootCerts(rootCAfile string, scanDate time.Time) error {
	tlsRootStores, err := LoadCCADBRoots(CCADBTLSTYPE, scanDate)
	if err != nil {
		log.Error().Err(err).Msg("Error loading CCADB TLS root certificates")
	}
	RootCertsPool[CCADBTLS], err = getCertPool(tlsRootStores)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of CCADB TLS root certificates")
	}

	sMimeRootStores, err := LoadCCADBRoots(CCADBSMIMETYPE, scanDate)
	if err != nil {
		log.Error().Err(err).Msg("Error loading CCADB s/MIME root certificates")
	}
	RootCertsPool[CCADBSMIME], err = getCertPool(sMimeRootStores)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of CCADB s/MIME root certificates")
	}

	if false {
		microsoftRootStores, err := LoadMicrosoftCodeSigningRoot()
		if err != nil {
			log.Error().Err(err).Msg("Warning! Could not load Microsoft root certificates")
		}
		RootCertsPool[MICROSOFTCODESIGNING], err = getCertPool(microsoftRootStores)
		if err != nil {
			log.Error().Err(err).Msg("Cannot get pool of Microsoft root certificates")
		}
	}

	googleRootCertsPool, err := getCertPoolFromPEMFile(GoogleServicesFile)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of Google services root certificates")
	}
	RootCertsPool[GOOGLESERVICES] = googleRootCertsPool

	applePool, err := getCertPoolFromPEMFile(AppleRootStoreFile)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of apple root certificates")
	}
	RootCertsPool[APPLE] = applePool

	windowsPool, err := getCertPoolFromDERFiles(WindowsRootStoreDir)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of Windows root certificates")
	}
	RootCertsPool[MICROSOFTWINDOWS] = windowsPool

	if rootCAfile != "" {
		customPool, err := getCertPoolFromPEMFile(rootCAfile)
		if err != nil {
			log.Error().Err(err).Msg("Cannot get pool of custom root certificates")
		}
		RootCertsPool[CUSTOM] = customPool
	}

	return nil
}

func getCertPool(rootCAs []string) (*x509.CertPool, error) {
	if len(rootCAs) == 0 {
		return nil, errors.New("no root CA file provided")
	}
	certPool := x509.NewCertPool()
	for _, rootCA := range rootCAs {
		if !certPool.AppendCertsFromPEM([]byte(rootCA)) {
			return nil, errors.New("failed to append root CA file certificate")
		}
	}
	return certPool, nil
}

func getCertPoolFromPEMFile(rootCAfile string) (*x509.CertPool, error) {
	timestampRootCAFile, err := misc.GetFile(rootCAfile)
	if err != nil {
		return nil, err
	}
	var certPool *x509.CertPool = nil
	if rootCAfile != "" {
		rootFile, err := os.ReadFile(timestampRootCAFile)
		if err != nil {
			return nil, err
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(rootFile) {
			return nil, errors.New("failed to append root CA file certificate to the pool")
		}
	}
	return certPool, nil
}

func getCertPoolFromDERFiles(rootCAFileDir string) (*x509.CertPool, error) {
	certs, err := os.ReadDir(rootCAFileDir)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	for _, cert := range certs {
		localFile := filepath.Join(rootCAFileDir, cert.Name())
		rootFile, err := os.ReadFile(localFile)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(rootFile)
		if err != nil {
			return nil, err
		}
		certPool.AddCert(cert)
	}
	return certPool, nil
}

func RemoveTemporary() {
	timestampFile, err := misc.GetFile(AppleRootStoreFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not get Apple file")
	}
	err = os.Remove(timestampFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove file.")
	}

	timestampFile, err = misc.GetFile(GoogleServicesFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not get Google services file")
	}
	err = os.Remove(timestampFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove file.")
	}

	timestampFile, err = misc.GetFile(TlsRootsFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not get CCADB TLS file")
	}
	err = os.Remove(timestampFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove file.")
	}

	timestampFile, err = misc.GetFile(SMimeRootsFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not get CCADB s/MIME file")
	}
	err = os.Remove(timestampFile)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove file.")
	}

	err = os.RemoveAll(WindowsRootStoreDir)
	if err != nil {
		log.Warn().Err(err).Msg("Could not remove Windows root store directory.")
	}
}
