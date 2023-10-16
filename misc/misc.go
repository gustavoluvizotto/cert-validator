package misc

import (
	"context"
	"encoding/csv"
	"errors"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog/log"
	"index/suffixarray"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	endpoint = "localhost:8080"
	bucket   = "catrin"
)

func LoadCsv(fileName string) ([][]string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		log.Error().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to read input file")
		return nil, err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Warn().Str("error", err.Error()).Msg("Failed to close the input file")
		}
	}(f)

	csvReader := csv.NewReader(f)

	// ignore header line
	_, err = csvReader.Read()
	if err != nil {
		log.Error().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to parse CSV file")
		return nil, err
	}
	// read all records
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Warn().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to parse CSV file")
		return nil, err
	}

	return records, nil
}

func Download(url string, filePath string) error {
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		err = out.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing file")
		}
	}(out)

	resp, err := http.Get(url)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error().Err(err).Msg("Error closing response body")
		}
	}(resp.Body)

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Error copying response body to file")
		return err
	}

	return nil
}

func GetMinioClient(profile string) (*minio.Client, error) {
	cred := credentials.NewFileAWSCredentials("credentials", profile)
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  cred,
		Secure: false,
	})
	if err != nil {
		return nil, err
	}
	return minioClient, nil
}

func UploadS3(minioClient *minio.Client, localFile string, remoteFile string) error {
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

func DownloadS3(minioClient *minio.Client, s3FilePrefix string, date time.Time, dirName string) error {
	var rootStoreS3File string
	listOpts := minio.ListObjectsOptions{
		Prefix:    s3FilePrefix,
		Recursive: true,
	}
	ctx := context.Background()
	for obj := range minioClient.ListObjects(ctx, bucket, listOpts) {
		if obj.Err != nil {
			return obj.Err
		}
		timestamp, err := time.Parse("20060102", strings.Split(filepath.Base(obj.Key), "_")[0])
		if err != nil {
			return err
		}
		// TODO remove true
		if timestamp.Before(date) || true {
			rootStoreS3File = obj.Key
			break
		}
	}

	obj, err := minioClient.GetObject(ctx, bucket, rootStoreS3File, minio.GetObjectOptions{Checksum: true})
	if err != nil {
		return err
	}
	defer func(obj *minio.Object) {
		err := obj.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing object.")
		}
	}(obj)

	fileName := dirName + filepath.Base(rootStoreS3File)
	localFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer func(localFile *os.File) {
		err := localFile.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing file.")
		}
	}(localFile)

	if _, err = io.Copy(localFile, obj); err != nil {
		return err
	}

	return nil
}

func GetFile(filePath string) (string, error) {
	dirName := filepath.Dir(filePath)
	extension := filepath.Ext(filePath)
	files, err := Find(dirName, extension)
	if err != nil {
		return "", err
	}
	fileName := filepath.Base(filePath)
	for _, file := range files {
		foundIdx := Contains(fileName, file)
		if len(foundIdx) > 0 {
			return file, nil
		}
	}
	return "", errors.New("file not found")
}

func Find(dir string, ext string) ([]string, error) {
	// https://stackoverflow.com/questions/55300117/how-do-i-find-all-files-that-have-a-certain-extension-in-go-regardless-of-depth
	var a []string
	err := filepath.WalkDir(dir, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

func Contains(needle string, haystack string) []int {
	index := suffixarray.New([]byte(haystack))

	// the list of all indices where needle occurs in haystack
	offsets := index.Lookup([]byte(needle), -1)

	return offsets
}
