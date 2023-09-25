package validator

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/result"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"time"
)

func ValidateChainPem(certChain input.CertChain, rootCAs *x509.CertPool, resultChan chan result.ValidationResult) {
	log.Debug().Int32("id", certChain.Id).Msg("Validating certificate chain")

	// Iterate over the certificates in the chain, permuting the leaf certificate and the intermediate certificates,
	// and verify the chain against the root CAs
	valResult := result.ValidationResult{Id: certChain.Id, IsValid: false}
	var leaf *x509.Certificate
	var err error
	isValid := false
	for i, certStr := range certChain.Chain {
		leaf, err = getCertificateFromPEM(certStr)
		if err != nil {
			continue
		}
		intermediates := x509.NewCertPool()
		for j, certStr2 := range certChain.Chain {
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

	valResult.IsValid = isValid
	if err != nil {
		valResult.ErrorData = err.Error()
	}
	resultChan <- valResult
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

func GetRootCAs(rootStores []string, rootCAfile string) (*x509.CertPool, error) {
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
