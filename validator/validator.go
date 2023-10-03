package validator

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/etnz/permute"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/result"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"strings"
	"time"
)

// max attempts to find other valid chains
const maxPermutations = 250000

func ValidateChainPem(certChain input.CertChain, rootCAs *x509.CertPool, resultChan chan result.ValidationResult, scanDate time.Time) {
	// rfc5280#section-4.2.1.12
	keyUsage := make([]x509.ExtKeyUsage, x509.ExtKeyUsageAny) // here we give a lower bound in our results
	valResult := result.ValidationResult{Id: *certChain.Id, IsValid: false}
	var err error
	var validChains [][]int32

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
	var intermediates *x509.CertPool
	for i := 1; i < len(certChain.Chain); i++ {
		intermediates = x509.NewCertPool()
		if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[i])) {
			valResult.ErrorData = "failed to append intermediate certificate"
			resultChan <- valResult
			log.Debug().Int32("id", *certChain.Id).Msg("Invalid certificate chain")
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
	_, err = leaf.Verify(opts)
	if err != nil {
		valResult.ErrorData = err.Error()
		resultChan <- valResult
		log.Debug().Int32("id", *certChain.Id).Msg("Invalid certificate chain")
		return
	}

	// valid chain
	var validChain []int32
	validChain = append(validChain, 0)
	for _, idx := range intermediateIdx {
		validChain = append(validChain, int32(idx))
	}
	validChains = append(validChains, validChain)

	// finding more chains
	var s [2]int
	h := permute.NewHeap(len(intermediateIdx))
	permutationCount := 0
	for h.Next(&s) {
		if permutationCount >= maxPermutations {
			break
		}
		permutationCount += 1

		permute.SwapInts(s, intermediateIdx)
		intermediates := x509.NewCertPool()
		var candidateValid []int32
		for _, idx := range intermediateIdx {
			if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[idx])) {
				err = errors.New("failed to append intermediate certificate")
				continue
			}
			candidateValid = append(candidateValid, int32(idx))
		}
		if err != nil {
			// could not append one of the intermediate certificates, meaning the cert is invalid
			continue
		}
		// Build the certificate verification options
		opts = x509.VerifyOptions{
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
		candidateValid = append([]int32{0}, candidateValid...)
		validChains = append(validChains, candidateValid)
	}

	valResult.IsValid = true
	valResult.ValidChains = strings.ReplaceAll(fmt.Sprint(validChains), " ", ", ")
	if err != nil {
		valResult.ErrorData = err.Error()
	}

	resultChan <- valResult
	log.Debug().Int("permutations", permutationCount+1).Int32("id", *certChain.Id).Msg("Validated certificate chain")
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
