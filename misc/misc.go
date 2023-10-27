package misc

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog/log"
	"index/suffixarray"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

func DownloadS3Files(minioClient *minio.Client, s3FilePrefix string, date time.Time, dirName string) error {
	var rootStoreS3FilesMap = make(map[string][]string)
	re := regexp.MustCompile(`.*(year=(\d{4})/month=(\d{2})/day=(\d{2})).*`)
	listOpts := minio.ListObjectsOptions{
		Prefix:    s3FilePrefix,
		Recursive: true,
	}
	ctx := context.Background()
	for obj := range minioClient.ListObjects(ctx, bucket, listOpts) {
		if obj.Err != nil {
			return obj.Err
		}
		matches := re.FindStringSubmatch(obj.Key)
		if matches == nil || len(matches) < 5 {
			return errors.New("no matches")
		}
		year := matches[2]
		month := matches[3]
		day := matches[4]
		timestamp, err := time.Parse("20060102", fmt.Sprintf("%s%s%s", year, month, day))
		if err != nil {
			return err
		}

		if timestamp.Before(date) || timestamp.Equal(date) {
			rootStoreS3FilesMap[matches[1]] = append(rootStoreS3FilesMap[matches[1]], obj.Key)
		}
	}

	datePaths := make([]string, 0, len(rootStoreS3FilesMap))
	for k := range rootStoreS3FilesMap {
		datePaths = append(datePaths, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(datePaths)))
	if len(datePaths) == 0 {
		return errors.New("no files found under prefix " + s3FilePrefix + " for date " + date.Format("20060102") + " or earlier")
	}
	datePath := datePaths[0]
	rootStoreS3Files := rootStoreS3FilesMap[datePath]

	if _, err := os.Stat(dirName); err != nil {
		err := os.MkdirAll(dirName, os.ModePerm)
		if err != nil {
			return err
		}
	}
	for _, rootStoreS3File := range rootStoreS3Files {
		err := downloadSingleFileS3(minioClient, ctx, rootStoreS3File, dirName)
		if err != nil {
			return err
		}
	}
	log.Info().Str("datePath", datePath).Str("dst", dirName).Msg("Successfully downloaded")

	return nil
}

func DownloadS3(minioClient *minio.Client, s3FilePrefix string, date time.Time, dirName string) error {
	var rootStoreS3Files []string
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

		if timestamp.Before(date) || timestamp.Equal(date) {
			rootStoreS3Files = append(rootStoreS3Files, obj.Key)
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(rootStoreS3Files)))
	if len(rootStoreS3Files) == 0 {
		return errors.New("no files found under prefix " + s3FilePrefix + " for date " + date.Format("20060102") + " or earlier")
	}
	rootStoreS3File := rootStoreS3Files[0]

	err := downloadSingleFileS3(minioClient, ctx, rootStoreS3File, dirName)
	if err != nil {
		return err
	}
	log.Info().Str("file", rootStoreS3File).Msg("Successfully downloaded")

	return nil
}

func downloadSingleFileS3(minioClient *minio.Client, ctx context.Context, rootStoreS3File string, dirName string) error {
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

func ExtractZip(zipFilePath string, extension string) error {
	archive, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return err
	}
	defer func(archive *zip.ReadCloser) {
		err := archive.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing archive.")
		}
	}(archive)

	for _, f := range archive.File {
		if extension != "" && filepath.Ext(f.Name) != extension {
			continue
		}
		baseDir := strings.TrimSuffix(zipFilePath, filepath.Ext(zipFilePath))
		filePath := filepath.Join(baseDir, f.Name)

		if err := os.MkdirAll(baseDir, os.ModePerm); err != nil {
			return err
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		srcFile, err := f.Open()
		if err != nil {
			_ = dstFile.Close()
			return err
		}

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			_ = srcFile.Close()
			_ = dstFile.Close()
			return err
		}

		_ = srcFile.Close()
		_ = dstFile.Close()
	}
	return nil
}
