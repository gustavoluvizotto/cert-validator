package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/gustavoluvizotto/cert-validator/rootstores"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"time"
)

const (
	endpoint = "localhost:8080"
	bucket   = "catrin"
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

	if portArg == 0 {
		log.Error().Msg("Port number is required")
		return
	}
	if scanDateArg == "" {
		log.Error().Msg("Scan date is required")
		return
	}
	if outputFile == "" {
		log.Error().Msg("Output file is required")
		return
	}

	minioClient, err := getMinioClient()
	if err != nil {
		log.Error().Err(err).Msg("Error getting Minio client")
		return
	}
	fileMap, err := getUploadFiles(portArg, scanDateArg, rootCAFile, logFile, outputFile)
	if err != nil {
		log.Error().Err(err).Msg("Error getting upload files")
		return
	}
	for localFile, remoteFile := range fileMap {
		err = upload(minioClient, localFile, remoteFile)
		if err != nil {
			log.Error().Err(err).Str("file", localFile).Msg("Error uploading file, try again...")
		} else {
			err = os.Remove(localFile)
			if err != nil {
				log.Warn().Err(err).Msg("Could not remove file.")
			}
		}
	}
}

func getMinioClient() (*minio.Client, error) {
	cred := credentials.NewFileAWSCredentials("credentials", "upload")
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  cred,
		Secure: false,
	})
	if err != nil {
		return nil, err
	}
	return minioClient, nil
}

func getUploadFiles(port int, scanDate string, rootCAFile string, logFile string, outputFile string) (map[string]string, error) {
	timestamp, err := time.Parse("20060102", scanDate)
	if err != nil {
		return nil, err
	}
	yearMonthDay := fmt.Sprintf("year=%04d/month=%02d/day=%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())
	timestampStr := fmt.Sprintf("%04d%02d%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())

	fileMap := make(map[string]string)

	// root store files
	rootstoreBasePath := "rootstores/format=raw"
	// skip microsoft code signing root store
	//fileMap[rootstores.MicrosoftCodeSigningFile] = fmt.Sprintf("%s/store=ccadb-microsoft/%s/%s_%s", rootstoreBasePath, yearMonthDay, timestampStr, filepath.Base(rootstores.MicrosoftCodeSigningFile))
	fileMap[rootstores.TlsRootsFile] = fmt.Sprintf("%s/store=ccadb-tls/%s/%s_%s", rootstoreBasePath, yearMonthDay, timestampStr, filepath.Base(rootstores.TlsRootsFile))
	fileMap[rootstores.SMimeRootsFile] = fmt.Sprintf("%s/store=ccadb-smime/%s/%s_%s", rootstoreBasePath, yearMonthDay, timestampStr, filepath.Base(rootstores.SMimeRootsFile))
	fileMap[rootstores.GoogleServicesFile] = fmt.Sprintf("%s/store=google/%s/%s_%s", rootstoreBasePath, yearMonthDay, timestampStr, filepath.Base(rootstores.GoogleServicesFile))
	if rootCAFile != "" {
		fileMap[rootCAFile] = fmt.Sprintf("%s/store=custom/%s/%s_%s", rootstoreBasePath, yearMonthDay, timestampStr, filepath.Base(rootCAFile))
	}

	// log file
	if logFile != "" {
		fileMap[logFile] = fmt.Sprintf("artefacts/tool=cert-validator/%s/%s_log.json", yearMonthDay, timestampStr)
	}

	// output file, e.g.:
	// data_processing/tool=cert-validator/format=parquet/port=389/year=2023/month=09/day=20/20230920_389_cert-validator.parquet
	fileMap[outputFile] = fmt.Sprintf("data_processing/tool=cert-validator/format=parquet/port=%d/%s/%s_%d_cert-validator.parquet", port, yearMonthDay, timestampStr, port)

	return fileMap, nil
}

func upload(minioClient *minio.Client, localFile string, remoteFile string) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing file.")
		}
	}(file)

	fileStat, err := file.Stat()
	if err != nil {
		return err
	}

	ctx := context.Background()
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true}
	uploadInfo, err := minioClient.PutObject(ctx, bucket, remoteFile, file, fileStat.Size(), opts)
	if err != nil {
		return err
	}

	log.Info().Str("ETag", uploadInfo.ETag).Msg("Successfully uploaded")

	return nil
}
