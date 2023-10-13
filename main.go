package main

import (
	"flag"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/prepare"
	"github.com/gustavoluvizotto/cert-validator/result"
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

	var noApple bool
	flag.BoolVar(&noApple,
		"no-apple",
		false,
		"Skip Apple root store")

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

	var certChains []input.CertChain
	if inputCsv != "" {
		certChains = input.LoadCsv(inputCsv)
	} else {
		certChains = input.LoadParquet(inputParquet)
	}

	if err = prepare.DownloadAllRootStores(noApple, scanDate); err != nil {
		return
	}

	validChainChan := validateChain(certChains, rootCAFile, scanDate, noApple)
	nrChains := len(certChains)
	result.ConsumeResultChannel(*validChainChan, nrChains, output)
}

func validateChain(certChains []input.CertChain, rootCAFile string, scanDate time.Time, noApple bool) *chan result.ValidationResult {
	err := validator.PoolRootCerts(rootCAFile, noApple)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading root certificates")
		return nil
	}
	validChainChan := make(chan result.ValidationResult, len(certChains))
	for _, certChain := range certChains {
		go validator.ValidateChainPem(certChain, validChainChan, scanDate)
	}
	return &validChainChan
}
