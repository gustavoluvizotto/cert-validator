package validator

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/etnz/permute"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/result"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"sync"
	"time"
)

var mtx sync.Mutex

func ValidateChainPem(certChain input.CertChain, rootCAs *x509.CertPool, resultChan chan result.ValidationResult, scanDate time.Time) {
	// rfc5280#section-4.2.1.12
	keyUsage := make([]x509.ExtKeyUsage, x509.ExtKeyUsageAny) // here we give a lower bound in our results
	valResult := result.ValidationResult{Id: *certChain.Id, IsValid: false}
	var leaf *x509.Certificate
	var err error
	isValid := false
	// Iterate over the certificates in the chain, permuting the leaf certificate and the intermediate certificates,
	// and verify the chain against the root CAs. Save all valid permutations
	for i, certStr := range certChain.Chain {
		leaf, err = getCertificateFromPEM(certStr)
		if err != nil {
			continue
		}

		var intermediateIdx []int
		for j, _ := range certChain.Chain {
			if i != j {
				intermediateIdx = append(intermediateIdx, j)
			}
		}

		var s [2]int
		h := permute.NewHeap(len(intermediateIdx))
		for h.Next(&s) {
			permute.SwapInts(s, intermediateIdx)
			intermediates := x509.NewCertPool()
			for _, idx := range intermediateIdx {
				if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[idx])) {
					err = errors.New("failed to append intermediate certificate")
					continue
				}
			}
			if err != nil {
				// could not append one of the intermediate certificates, meaning the cert is invalid
				continue
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
			_, err = leaf.Verify(opts)
			if err != nil {
				continue
			}
			isValid = true
			break
		}
		if isValid {
			break
		}
	}

	valResult.IsValid = isValid
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
