package validator

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"time"
)

func ValidateChainPem(certChainStr []string, rootStores []string, rootCAFile string) (bool, error) {
	rootCAs, err := getRootCAs(rootStores, rootCAFile)
	if err != nil {
		log.Fatal().Msg(err.Error())
		return false, err
	}

	// Iterate over the certificates in the chain, permuting the leaf certificate and the intermediate certificates,
	// and verify the chain against the root CAs
	var leaf *x509.Certificate
	isValid := false
	for i, certStr := range certChainStr {
		leaf, err = getCertificateFromPEM(certStr)
		if err != nil {
			continue
		}
		intermediates := x509.NewCertPool()
		for j, certStr2 := range certChainStr {
			if i != j {
				if !intermediates.AppendCertsFromPEM([]byte(certStr2)) {
					err = errors.New("failed to append intermediate certificate")
					continue
				}
			}
		}
		// Build the certificate verification options
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			CurrentTime:   time.Now(),
			Intermediates: intermediates,
		}

		// Verify the certificate chain
		_, err = leaf.Verify(opts)
		if err != nil {
			continue
		}
		isValid = true
		break
	}

	return isValid, err
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

func getRootCAs(rootStores []string, rootCAfile string) (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("failed to fetch system root CA certificates")
	}
	for i, rootStore := range rootStores {
		if !rootCAs.AppendCertsFromPEM([]byte(rootStore)) {
			return nil, errors.New("failed to append CA certificate " + strconv.Itoa(i) + " from root stores")
		}
	}
	if rootCAfile != "" {
		rootFile, err := os.ReadFile(rootCAfile)
		if err != nil {
			return nil, errors.New("failed to read " + rootCAfile)
		}
		if !rootCAs.AppendCertsFromPEM(rootFile) {
			return nil, errors.New("failed to append root CA file certificate")
		}
	}
	return rootCAs, nil
}
