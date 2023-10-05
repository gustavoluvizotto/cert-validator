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
	"time"
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

	var output string
	flag.StringVar(&output,
		"output",
		"",
		"The output file in Parquet format (provide extension)")

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

	var scanDateArg string
	flag.StringVar(&scanDateArg,
		"scan-date",
		"",
		"Date the certificates were collected. Format: YYYYMMDD")
	flag.Parse()

	log.Logger = log.Output(zerolog.NewConsoleWriter())

	if verbosity >= 2 {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else if verbosity == 1 {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	if output == "" {
		log.Fatal().Msg("Output file is required")
		return
	}
	if scanDateArg == "" {
		log.Fatal().Msg("Scan date is required")
		return
	}
	scanDate, err := time.Parse("20060102", scanDateArg)
	if err != nil {
		log.Fatal().Msg("Incorrect format for scan date argument. Use YYYYMMDD")
		return
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
			log.Fatal().Err(err).Msg("Error loading CCADB TLS root certificates")
			return
		}
		rootStores = append(rootStores, tlsRootStores...)
	} else if useSmimeRoot {
		sMimeRootStores, err := rootstores.LoadTlsRoots(rootstores.SMIME)
		if err != nil {
			log.Fatal().Err(err).Msg("Error loading CCADB sMIME root certificates")
			return
		}
		rootStores = append(rootStores, sMimeRootStores...)
	}
	microsoftRootStores, err := rootstores.LoadMicrosoftRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Warning! Could not load Microsoft root certificates")
	}
	rootStores = append(rootStores, microsoftRootStores...)

	err = rootstores.DownloadGoogleServicesRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Warning! Could not download Google services root certificates")
	}

	var certChains []input.CertChain
	if inputCsv != "" {
		certChains = input.LoadCsv(inputCsv)
	} else {
		certChains = input.LoadParquet(inputParquet)
	}

	validChainChan := validateChain(certChains, rootStores, rootCAFile, scanDate)
	nrChains := len(certChains)
	result.ConsumeResultChannel(*validChainChan, nrChains, output)
}

func validateChain(certChains []input.CertChain, rootStores []string, rootCAFile string, scanDate time.Time) *chan result.ValidationResult {
	rootCAs, err := validator.GetRootCAs(rootStores, rootCAFile)
	if err != nil {
		log.Fatal().Msg(err.Error())
		return nil
	}
	validChainChan := make(chan result.ValidationResult, len(certChains))
	for _, certChain := range certChains {
		go validator.ValidateChainPem(certChain, rootCAs, validChainChan, scanDate)
	}
	return &validChainChan
}
