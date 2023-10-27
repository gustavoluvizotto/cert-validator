package main

import (
	"flag"
	"fmt"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var logFile string
	flag.StringVar(&logFile,
		"log-file",
		"",
		"Path to the log file")

	var outputFile string
	flag.StringVar(&outputFile,
		"output",
		"",
		"Path to output file")

	var portArg int
	flag.IntVar(&portArg,
		"port",
		0,
		"Port number to add to the upload path")

	var rootCAFile string
	flag.StringVar(&rootCAFile,
		"root-ca-file",
		"",
		"Path to custom root store file")

	var scanDateArg string
	flag.StringVar(&scanDateArg,
		"scan-date",
		"",
		"Date the certificates were collected. Format: YYYYMMDD")

	flag.Parse()

	log.Logger = log.Output(zerolog.NewConsoleWriter())
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if outputFile == "" {
		log.Fatal().Msg("Output file is required")
	}
	if portArg == 0 {
		log.Fatal().Msg("Port number is required")
	}
	if scanDateArg == "" {
		log.Fatal().Msg("Scan date is required")
	}

	minioClient, err := misc.GetMinioClient("upload")
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting Minio client")
	}
	fileMap, err := getFileMap(portArg, scanDateArg, rootCAFile, logFile, outputFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting upload files")
	}
	for localFile, remoteFile := range fileMap {
		err = misc.UploadS3(minioClient, localFile, remoteFile)
		if err != nil {
			log.Error().Err(err).Str("file", localFile).Msg("Error uploading file, try again...")
		} else {
			err2 := os.Remove(localFile)
			if err2 != nil {
				log.Warn().Err(err2).Msg("Could not remove file.")
			}
		}
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Error uploading files, please check logs")
	}
}

func getFileMap(port int, scanDate string, rootCAFile string, logFile string, outputFile string) (map[string]string, error) {
	timestamp, err := time.Parse("20060102", scanDate)
	if err != nil {
		return nil, err
	}
	yearMonthDay := fmt.Sprintf("year=%04d/month=%02d/day=%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())
	timestampStr := fmt.Sprintf("%04d%02d%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())

	fileMap := make(map[string]string)

	if logFile != "" {
		fileMap[logFile] = fmt.Sprintf("artefacts/tool=cert-validator/%s/%s_log.json", yearMonthDay, timestampStr)
	}

	// output file, e.g.:
	// data_processing/tool=cert-validator/format=parquet/port=389/year=2023/month=09/day=20/20230920_389_cert-validator.parquet
	fileMap[outputFile] = fmt.Sprintf("data_processing/tool=cert-validator/format=parquet/port=%d/%s/%s_%d_cert-validator.parquet", port, yearMonthDay, timestampStr, port)

	if rootCAFile != "" {
		fileMap[rootCAFile] = fmt.Sprintf("rootstores/format=raw/store=custom/%s/%s_%s", yearMonthDay, timestampStr, filepath.Base(rootCAFile))
	}

	return fileMap, nil
}
