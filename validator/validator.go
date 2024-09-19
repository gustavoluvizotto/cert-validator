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
		Id:                *certChain.Id,
		RootStores:        make(map[string]result.RootStoreResult),
		AllValidLeafIndex: make([]int32, 0),
	}

	// try all leaf certs to find whether at least one is valid
	for leafIndex := 0; leafIndex < len(certChain.Chain); leafIndex++ {
		leaf, err := getCertificateFromPEM(certChain.Chain[leafIndex])

		if err != nil {
			valResult.Error = "Chain has no valid leaf certificate"
			resultChan <- valResult
			log.Debug().Int32("id", *certChain.Id).Msg(valResult.Error)
			continue
		}

		// discard leaf that are marked as CA
		if leaf.IsCA {
			continue
		}

		// building the intermediates pool, avoiding add the leaf certificate
		leafFp := x509util.Fingerprint(leaf)
		intermediates := x509.NewCertPool()
		for i := 0; i < len(certChain.Chain); i++ {
			intermediate, err := getCertificateFromPEM(certChain.Chain[i])
			var intermediateFp string
			if err == nil {
				intermediateFp = x509util.Fingerprint(intermediate)
				// do not add the current leaf certificate to the intermediates pool
				if leafFp == intermediateFp {
					continue
				}
			}
			if err == nil && !intermediate.IsCA {
				log.Debug().Int("leafIndex", leafIndex).Int32("chainId", *certChain.Id).Int("index", i).Bool("isCA", intermediate.IsCA).Str("subject.CN", intermediate.Subject.CommonName).Msg("Intermediate certificate did not set the flag")
				continue
			}
			if !intermediates.AppendCertsFromPEM([]byte(certChain.Chain[i])) {
				valResult.Error = "failed to append intermediate certificate: " + strings.ToUpper(intermediateFp)
				resultChan <- valResult
				log.Debug().Int32("id", *certChain.Id).Msg(valResult.Error)
				return
			}
		}

		// result for the current leaf
		leafRootRes := make(map[string]result.RootStoreResult)
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
				leafRootRes[storeName] = rootStore
				continue
			}

			var validChainsFp [][]string
			for _, validChain := range validChains {
				var validChainFp []string
				for _, cert := range validChain {
					// quoting to be able to eval in during analysis (analysis of the output)
					fp := strconv.Quote(strings.ToUpper(x509util.Fingerprint(cert)))
					validChainFp = append(validChainFp, fp)
				}
				validChainsFp = append(validChainsFp, validChainFp)
			}
			rootStore.ValidChains = strings.ReplaceAll(fmt.Sprint(validChainsFp), " ", ", ")

			rootStore.IsValid = true // err == nil from x509.Verify, then there exist one or more valid chains
			leafRootRes[storeName] = rootStore

		} // end of all root store loop

		// last valid leaf is stored
		if anyValidChain(leafRootRes) {
			valResult.RootStores = leafRootRes
			valResult.LeafCertIndex = int32(leafIndex)
			valResult.AllValidLeafIndex = append(valResult.AllValidLeafIndex, int32(leafIndex))
		}
		// if no valid chain is found, at least the first leaf is stored
		if len(valResult.RootStores) == 0 {
			valResult.RootStores = leafRootRes
			valResult.LeafCertIndex = int32(leafIndex)
		}
	} // end of leaf certificate loop

	resultChan <- valResult
	log.Debug().Int32("id", *certChain.Id).Msg("Processed certificate chain")
}

func anyValidChain(resultRootStores map[string]result.RootStoreResult) bool {
	for _, rootStore := range resultRootStores {
		if rootStore.IsValid {
			return true
		}
	}
	return false
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
