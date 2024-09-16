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
	"strconv"
	"strings"
	"time"
)

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
	leafFp := x509util.Fingerprint(leaf)
	//var intermediateIdx []int
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certChain.Chain); i++ {
		// do not add the leaf certificate to the intermediates pool
		intermediate, err := getCertificateFromPEM(certChain.Chain[i])
		var intermediateFp string
		if err == nil {
			intermediateFp = x509util.Fingerprint(intermediate)
			if leafFp == intermediateFp {
				continue
			}
		}
		if err == nil && !intermediate.IsCA {
			log.Debug().Int32("chainId", *certChain.Id).Int("index", i).Bool("isCA", intermediate.IsCA).Str("subject.CN", intermediate.Subject.CommonName).Msg("Intermediate certificate did not set the flag")
			continue
		}
		if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[i])) {
			valResult.Error = "failed to append intermediate certificate: " + strings.ToUpper(intermediateFp)
			resultChan <- valResult
			log.Debug().Int32("id", *certChain.Id).Msg(valResult.Error)
			return
		}
		//intermediateIdx = append(intermediateIdx, i)
	}

	// rfc5280#section-4.2.1.12
	keyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageAny} // here we give a lower bound to our results
	for storeName, rootCAs := range rootstores.RootCertsPool {
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
