package main

import (
    "flag"
    "github.com/gustavoluvizotto/cert-validator/input"
    "github.com/gustavoluvizotto/cert-validator/result"
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

    var certChains []input.CertChain
    if inputCsv != "" {
        certChains = input.LoadCsv(inputCsv)
    } else {
        certChains = input.LoadParquet(inputParquet)
    }

    validChains := validateChain(certChains)

    result.StoreResult(validChains, "example/output-sample.parquet")
}

func validateChain(certChains []input.CertChain) []result.ValidationResult {
    var validChains []result.ValidationResult
    for _, v := range certChains {
        log.Debug().Int32("id", v.Id).Strs("chain", v.Chain).Msg("Loaded certificate chain")
        isValid := validator.ValidateChainPem(v.Chain)
        validChains = append(validChains, result.ValidationResult{Id: v.Id, Chain: v.Chain, IsValid: isValid})
    }
    return validChains
}
