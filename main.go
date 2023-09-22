package main

import (
	"flag"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/result"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/gustavoluvizotto/cert-validator/validator"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

func main() {
	// parse command line arguments
	var inputParquet string
	flag.StringVar(&inputParquet,
		"input-parquet",
		"example/input-sample.parquet",
		"The input file in Parquet format")

	var inputCsv string
	flag.StringVar(&inputCsv,
		"input-csv",
		"",
		"The input file in CSV format")

	var logFile string
	flag.StringVar(&logFile,
		"log-file",
		"",
		"The log file in JSON format")

	// default value is no verbosity
	var verbosity int
	flag.IntVar(&verbosity,
		"v",
		0,
		"Verbosity level (1 or 2)")

	var useTlsRoot bool
	flag.BoolVar(&useTlsRoot,
		"tls-root",
		false,
		"Use TLS root store from CCADB")
	var useSmimeRoot bool
	flag.BoolVar(&useSmimeRoot,
		"smime-root",
		false,
		"Use sMIME root store from CCADB")
	var rootCAFile string
	flag.StringVar(&rootCAFile,
		"root-ca-file",
		"",
		"Use root store from PEM file")
	flag.Parse()

	log.Logger = log.Output(zerolog.NewConsoleWriter())

	if verbosity >= 2 {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else if verbosity == 1 {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	if logFile != "" {
		fh, err := os.Create(logFile)
		if err != nil {
			log.Fatal().Err(err).Str("file", logFile).Msg("Error creating log file")
		}
		log.Logger = log.Output(fh)
	}

	var rootStores []string
	if useTlsRoot {
		tlsRootStores, err := rootstores.LoadTlsRoots(rootstores.TLS)
		if err != nil {
			log.Fatal().Err(err).Msg("Error downloading TLS roots")
			return
		}
		rootStores = append(rootStores, tlsRootStores...)
	} else if useSmimeRoot {
		sMimeRootStores, err := rootstores.LoadTlsRoots(rootstores.SMIME)
		if err != nil {
			log.Fatal().Err(err).Msg("Error downloading sMIME roots")
			return
		}
		rootStores = append(rootStores, sMimeRootStores...)
	}

	var certChains []input.CertChain
	if inputCsv != "" {
		certChains = input.LoadCsv(inputCsv)
	} else {
		certChains = input.LoadParquet(inputParquet)
	}

	validChains := validateChain(certChains, rootStores, rootCAFile)

	result.StoreResult(validChains, "example/output-sample.parquet")
}

func validateChain(certChains []input.CertChain, rootStores []string, rootCAFile string) []result.ValidationResult {
	var validChains []result.ValidationResult
	for _, v := range certChains {
		log.Debug().Int32("id", v.Id).Msg("Loaded certificate chain")
		isValid, err := validator.ValidateChainPem(v.Chain, rootStores, rootCAFile)
		var errStr string
		if err != nil {
			errStr = err.Error()
		}
		validChains = append(validChains, result.ValidationResult{Id: v.Id, Error: errStr, IsValid: isValid})
	}
	return validChains
}
