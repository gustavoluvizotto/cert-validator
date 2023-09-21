package validator

import (
    "crypto/x509"
    "encoding/pem"
    "github.com/rs/zerolog/log"
    "time"
)

func ValidateChainPem(certChainStr []string) bool {
    var certChain []*x509.Certificate

    for _, certStr := range certChainStr {
        block, _ := pem.Decode([]byte(certStr))
        if block == nil {
            log.Info().Str("cert", certStr).Msg("Failed to parse PEM block")
            return false
        }

        if block.Type != "CERTIFICATE" {
            log.Info().Str("cert", certStr).Str("blockType", block.Type).Msg("Expected CERTIFICATE block")
            return false
        }

        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            log.Info().Str("cert", certStr).Str("error", err.Error()).Msg("Failed to parse certificate")
            return false
        }

        certChain = append(certChain, cert)
    }

    rootCAs := systemStoreCAs()

    // Build the certificate verification options
    opts := x509.VerifyOptions{
        Roots:         rootCAs,
        CurrentTime:   time.Now(),
        Intermediates: x509.NewCertPool(),
    }

    // Verify the certificate chain
    _, err := certChain[0].Verify(opts)
    if err != nil {
        log.Info().Strs("chain", certChainStr).Str("error", err.Error()).Msg("Certificate chain validation failed")
        return false
    }

    log.Info().Strs("chain", certChainStr).Msg("Certificate chain is valid.")
    return true
}

func systemStoreCAs() *x509.CertPool {
    rootCAs, err := x509.SystemCertPool()
    if err != nil {
        log.Info().Str("error", err.Error()).Msg("Failed to fetch system root CA certificates")
        return nil
    }

    return rootCAs
}
