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

func ValidateChainPem(certChain input.CertChain, rootCAs *x509.CertPool, resultChan chan result.ValidationResult, scanDate time.Time) {
	// rfc5280#section-4.2.1.12
	keyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageAny} // here we give a lower bound in our results
	valResult := result.ValidationResult{Id: *certChain.Id, IsValid: false}
	var err error

	// first element of the chain is the leaf certificate
	leaf, err := getCertificateFromPEM(certChain.Chain[0])
	if err != nil {
		valResult.ErrorData = "Chain has no valid leaf certificate"
		resultChan <- valResult
		log.Debug().Int32("id", *certChain.Id).Msg(valResult.ErrorData)
		return
	}

	// Iterate over the certificates in the chain, permuting the leaf certificate and the intermediate certificates,
	// and verify the chain against the root CAs. Save all valid permutations
	//var leaf *x509.Certificate
	var intermediateIdx []int
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certChain.Chain); i++ {
		if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[i])) {
			valResult.ErrorData = "failed to append intermediate certificate"
			resultChan <- valResult
			log.Debug().Int32("id", *certChain.Id).Msg(valResult.ErrorData)
			return
		}
		intermediateIdx = append(intermediateIdx, i)
	}

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
		valResult.ErrorData = err.Error()
		resultChan <- valResult
		log.Debug().Int32("id", *certChain.Id).Msg("Invalid certificate chain")
		return
	}

	var validChainsFp [][]string
	for _, validChain := range validChains {
		var validChainFp []string
		for _, cert := range validChain {
			fp := strconv.Quote(strings.ToUpper(x509util.Fingerprint(cert)))
			validChainFp = append(validChainFp, fp)
		}
		validChainsFp = append(validChainsFp, validChainFp)
	}

	valResult.IsValid = true
	valResult.ValidChains = strings.ReplaceAll(fmt.Sprint(validChainsFp), " ", ", ")
	if err != nil {
		valResult.ErrorData = err.Error()
	}

	resultChan <- valResult
	log.Debug().Int32("id", *certChain.Id).Msg("Validated certificate chain")
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

	if rootCAfile != "" {
		rootFile, err := os.ReadFile(rootCAfile)
		if err != nil {
			return nil, errors.New("failed to read " + rootCAfile)
		}
		if !rootCAs.AppendCertsFromPEM(rootFile) {
			return nil, errors.New("failed to append root CA file certificate")
		}
	}

	_, err = os.Stat(rootstores.GoogleServicesFile)
	if err == nil {
		rootFile, err := os.ReadFile(rootstores.GoogleServicesFile)
		if err != nil {
			return nil, errors.New("failed to read " + rootstores.GoogleServicesFile)
		}
		if !rootCAs.AppendCertsFromPEM(rootFile) {
			return nil, errors.New("failed to append Google services root CAs certificates")
		}
		err = os.Remove(rootstores.GoogleServicesFile)
		if err != nil {
			log.Info().Err(err).Msg("Error removing file")
		}
	}

	for i, rootStore := range rootStores {
		if !rootCAs.AppendCertsFromPEM([]byte(rootStore)) {
			return nil, errors.New("failed to append CA certificate " + strconv.Itoa(i) + " from root stores")
		}
	}

	return rootCAs, nil
}
