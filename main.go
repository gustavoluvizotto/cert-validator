package main

import (
	"flag"
	"github.com/gustavoluvizotto/cert-validator/input"
	"github.com/gustavoluvizotto/cert-validator/prepare"
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
	var inputCsv string
	flag.StringVar(&inputCsv,
		"input-csv",
		"",
		"The input file in CSV format")

	var inputParquet string
	flag.StringVar(&inputParquet,
		"input-parquet",
		"example/input-sample.parquet",
		"The input file in Parquet format")

	var logFile string
	flag.StringVar(&logFile,
		"log-file",
		"",
		"The log file in JSON format")

	var output string
	flag.StringVar(&output,
		"output",
		"",
		"The output file in Parquet format (provide extension)")

	var prep bool
	flag.BoolVar(&prep,
		"prep",
		false,
		"Preparation step; download root stores")

	var rM bool
	flag.BoolVar(&rM,
		"rm",
		false,
		"Remove temporary files")

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

	// default value is no verbosity
	var verbosity int
	flag.IntVar(&verbosity,
		"v",
		0,
		"Verbosity level (1 or 2)")

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

	if scanDateArg == "" {
		log.Fatal().Msg("Scan date is required")
	}
	scanDate, err := time.Parse("20060102", scanDateArg)
	if err != nil {
		log.Fatal().Str("scanDateArg", scanDateArg).Msg("Incorrect format for scan date argument. Use YYYYMMDD")
	}

	if prep {
		err := prepare.RetrieveAllRootStores(scanDate)
		if err != nil {
			log.Fatal().Err(err).Msg("Error retrieving root stores")
		}
		return
	}

	if output == "" {
		log.Fatal().Msg("Output file is required")
	}

	logInputs(inputCsv, inputParquet, logFile, output, rM, rootCAFile, scanDateArg, verbosity)

	var certChains []input.CertChain
	if inputCsv != "" {
		certChains = input.LoadCsv(inputCsv)
	} else {
		certChains = input.LoadParquet(inputParquet)
	}
	if certChains == nil || len(certChains) == 0 {
		log.Fatal().Msg("No certificate chain to validate")
	}

	startTime := time.Now()
	validChainChan := validateChain(certChains, rootCAFile, scanDate)
	nrChains := len(certChains)
	result.ConsumeResultChannel(*validChainChan, nrChains, output)
	endTime := time.Now()

	if rM {
		rootstores.RemoveDownloadedRootCertificates()
	}

	log.Info().Str("validationTime", endTime.Sub(startTime).String()).Msg("Validation time")
}

func logInputs(inputCsv string, inputParquet string, logFile string, output string, rM bool, rootCAFile string, scanDate string, verbosity int) {
	log.Info().Str("input-csv", inputCsv).Str("input-parquet", inputParquet).Str("log-file", logFile).Str("output", output).Bool("rm", rM).Str("root-ca-file", rootCAFile).Str("scan-date", scanDate).Int("verbosity", verbosity).Msg("Inputs")
}

func validateChain(certChains []input.CertChain, rootCAFile string, scanDate time.Time) *chan result.ValidationResult {
	err := rootstores.PoolRootCerts(rootCAFile, scanDate)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading root certificates")
	}
	if rootstores.IsEmptyRootCertsPool() {
		log.Fatal().Msg("No root certificates loaded")
	}

	validChainChan := make(chan result.ValidationResult, len(certChains))
	for _, certChain := range certChains {
		go validator.ValidateChainPem(certChain, validChainChan, scanDate)
	}

	return &validChainChan
}
