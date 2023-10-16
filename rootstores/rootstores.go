package rootstores

import (
	"crypto/x509"
	"errors"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/rs/zerolog/log"
	"os"
)

const (
	CCADBTLS             = "CCADBTLS"
	CCADBSMIME           = "CCADBSMIME"
	MICROSOFTCODESIGNING = "MICROSOFTCODESIGNING"
	GOOGLESERVICES       = "GOOGLESERVICES"
	APPLE                = "APPLE"
	CUSTOM               = "CUSTOM"
)

var RootCertsPool = map[string]*x509.CertPool{
	CCADBTLS:       nil,
	CCADBSMIME:     nil,
	GOOGLESERVICES: nil,
	APPLE:          nil,
	//MICROSOFTCODESIGNING: nil,
}

func PoolRootCerts(rootCAfile string, noApple bool) error {
	tlsRootStores, err := LoadCCADBRoots(CCADBTLSTYPE)
	if err != nil {
		log.Error().Err(err).Msg("Error loading CCADB TLS root certificates")
		return err
	}
	RootCertsPool[CCADBTLS], err = getCertPool(tlsRootStores)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of CCADB TLS root certificates")
		return err
	}

	sMimeRootStores, err := LoadCCADBRoots(CCADBSMIMETYPE)
	if err != nil {
		log.Error().Err(err).Msg("Error loading CCADB s/MIME root certificates")
		return err
	}
	RootCertsPool[CCADBSMIME], err = getCertPool(sMimeRootStores)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of CCADB s/MIME root certificates")
		return err
	}

	if false {
		microsoftRootStores, err := LoadMicrosoftCodeSigningRoot()
		if err != nil {
			log.Error().Err(err).Msg("Warning! Could not load Microsoft root certificates")
			return err
		}
		RootCertsPool[MICROSOFTCODESIGNING], err = getCertPool(microsoftRootStores)
		if err != nil {
			log.Error().Err(err).Msg("Cannot get pool of Microsoft root certificates")
			return err
		}
	}
	googleRootCertsPool, err := getCertPoolFromPEMFile(GoogleServicesFile)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of Google services root certificates")
		return err
	}
	RootCertsPool[GOOGLESERVICES] = googleRootCertsPool

	if !noApple {
		applePool, err := getCertPoolFromPEMFile(AppleRootStoreFile)
		if err != nil {
			log.Error().Err(err).Msg("Cannot get pool of apple root certificates")
			return err
		}
		RootCertsPool[APPLE] = applePool
	}

	customPool, err := getCertPoolFromPEMFile(rootCAfile)
	if err != nil {
		log.Error().Err(err).Msg("Cannot get pool of custom root certificates")
		return err
	}
	RootCertsPool[CUSTOM] = customPool

	return nil
}

func getCertPool(rootCAs []string) (*x509.CertPool, error) {
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
}
