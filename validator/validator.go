package validator

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/result"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/rs/zerolog/log"
	"go.step.sm/crypto/x509util"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	CCADBTLS             = "CCADBTLS"
	CCADBSMIME           = "CCADBSMIME"
	MICROSOFTCODESIGNING = "MICROSOFTCODESIGNING"
	GOOGLE               = "GOOGLE"
	APPLE                = "APPLE"
	CUSTOM               = "CUSTOM"
)

var RootCertsPool = map[string]*x509.CertPool{
	CCADBTLS:   nil,
	CCADBSMIME: nil,
	GOOGLE:     nil,
	APPLE:      nil,
	//MICROSOFTCODESIGNING: nil,
}

func ValidateChainPem(certChain input.CertChain, resultChan chan result.ValidationResult, scanDate time.Time) {
	valResult := result.ValidationResult{
		Id:         *certChain.Id,
		RootStores: make(map[string]result.RootStoreResult),
	}

	// first element of the chain is the leaf certificate
	leaf, err := getCertificateFromPEM(certChain.Chain[0])
	if err != nil {
		valResult.Error = "Chain has no valid leaf certificate"
		resultChan <- valResult
		log.Debug().Int32("id", *certChain.Id).Msg(valResult.Error)
		return
	}

	// Iterate over the certificates in the chain, permuting the leaf certificate and the intermediate certificates,
	// and verify the chain against the root CAs. Save all valid permutations
	//var leaf *x509.Certificate
	var intermediateIdx []int
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certChain.Chain); i++ {
		// do not add the leaf certificate to the intermediates pool
		intermediate, err := getCertificateFromPEM(certChain.Chain[i])
		var intermediateFp string
		if err == nil {
			leafFp := x509util.Fingerprint(leaf)
			intermediateFp = x509util.Fingerprint(intermediate)
			if leafFp == intermediateFp {
				continue
			}
		}

		if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[i])) {
			valResult.Error = "failed to append intermediate certificate: " + strings.ToUpper(intermediateFp)
			resultChan <- valResult
			log.Debug().Int32("id", *certChain.Id).Msg(valResult.Error)
			return
		}
		intermediateIdx = append(intermediateIdx, i)
	}

	// rfc5280#section-4.2.1.12
	keyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageAny} // here we give a lower bound to our results
	for storeName, rootCAs := range RootCertsPool {
		if rootCAs == nil {
			continue
		}

		rootStore := result.RootStoreResult{IsValid: false}

		// Build the certificate verification options
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			CurrentTime:   scanDate,
			Intermediates: intermediates,
			DNSName:       "",
			KeyUsages:     keyUsage,
		}
		// Verify the certificate chain
		validChains, err := leaf.Verify(opts)
		if err != nil {
			rootStore.Error = err.Error()
			valResult.RootStores[storeName] = rootStore
			continue
		}

		var validChainsFp [][]string
		for _, validChain := range validChains {
			var validChainFp []string
			for _, cert := range validChain {
				// quoting to be able to eval in analysis phase
				fp := strconv.Quote(strings.ToUpper(x509util.Fingerprint(cert)))
				validChainFp = append(validChainFp, fp)
			}
			validChainsFp = append(validChainsFp, validChainFp)
		}
		rootStore.ValidChains = strings.ReplaceAll(fmt.Sprint(validChainsFp), " ", ", ")

		rootStore.IsValid = true
		if err != nil {
			rootStore.Error = err.Error()
		}
		valResult.RootStores[storeName] = rootStore
	}

	resultChan <- valResult
	log.Debug().Int32("id", *certChain.Id).Msg("Processed certificate chain")
}

func getCertificateFromPEM(certStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("expected CERTIFICATE block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func PoolRootCerts(rootCAfile string, noApple bool) error {
	tlsRootStores, err := rootstores.LoadCCADBRoots(rootstores.TLS)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading CCADB TLS root certificates")
		return err
	}
	RootCertsPool[CCADBTLS], err = getCertPool(tlsRootStores)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot get pool of CCADB TLS root certificates")
		return err
	}

	sMimeRootStores, err := rootstores.LoadCCADBRoots(rootstores.SMIME)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading CCADB s/MIME root certificates")
		return err
	}
	RootCertsPool[CCADBSMIME], err = getCertPool(sMimeRootStores)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot get pool of CCADB s/MIME root certificates")
		return err
	}

	if false {
		microsoftRootStores, err := rootstores.LoadMicrosoftCodeSigningRoot()
		if err != nil {
			log.Fatal().Err(err).Msg("Warning! Could not load Microsoft root certificates")
			return err
		}
		RootCertsPool[MICROSOFTCODESIGNING], err = getCertPool(microsoftRootStores)
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot get pool of Microsoft root certificates")
			return err
		}
	}
	googleRootCertsPool, err := getCertPoolFromFile(rootstores.GoogleServicesFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot get pool of Google services root certificates")
		return err
	}
	RootCertsPool[GOOGLE] = googleRootCertsPool

	if !noApple {
		applePool, err := getCertPoolFromFile(rootstores.AppleRootStoreFile)
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot get pool of custom root certificates")
			return err
		}
		RootCertsPool[APPLE] = applePool
		err = os.Remove(rootstores.AppleRootStoreFile)
		if err != nil {
			log.Warn().Err(err).Msg("Could not remove file.")
		}
	}

	customPool, err := getCertPoolFromFile(rootCAfile)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot get pool of custom root certificates")
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

func getCertPoolFromFile(rootCAfile string) (*x509.CertPool, error) {
	var certPool *x509.CertPool = nil
	if rootCAfile != "" {
		rootFile, err := os.ReadFile(rootCAfile)
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
