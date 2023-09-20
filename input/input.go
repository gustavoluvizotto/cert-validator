package input

import (
	"encoding/csv"
	"encoding/json"
	"github.com/rs/zerolog/log"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/reader"
	"github.com/xitongsys/parquet-go/source"
	"os"
	"strconv"
	"strings"
)

// Struct for the parquet file schema:
// root
// |-- id: integer (nullable = true)
// |-- chain: array (nullable = true)
// |    |-- element: string (containsNull = true)
type CertChain struct {
	Id    int32    `parquet:"name=id, type=INT32"`
	Chain []string `parquet:"name=chain, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
}

func LoadCsv(fileName string) []CertChain {
	f, err := os.Open(fileName)
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to read input file")
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Fatal().Str("error", err.Error()).Msg("Failed to close the input file")
		}
	}(f)

	csvReader := csv.NewReader(f)

	// ignore header line
	_, err = csvReader.Read()
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to parse CSV file")
	}
	// read all records
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to parse CSV file")
	}

	// loop through records and convert to CertChain
	n := len(records)
	certChains := make([]CertChain, n)
	for i, v := range records {
		id, _ := strconv.Atoi(v[0])
		var pemCerts []string
		jsonInput := strings.ReplaceAll(v[1], "'", "\"")
		if err := json.Unmarshal([]byte(jsonInput), &pemCerts); err != nil {
			log.Fatal().Str("error", err.Error()).Msg("Unable to parse JSON input")
			return nil
		}
		certChains[i] = CertChain{
			Id:    int32(id),
			Chain: pemCerts,
		}
	}

	return certChains
}

func LoadParquet(fileName string) []CertChain {
	// FIXME this is not working
	fr, err := local.NewLocalFileReader(fileName)
	if err != nil {
		log.Fatal().Str("file", fileName).Str("error", err.Error()).Msg("Failed to open file")
		return nil
	}
	defer func(fr source.ParquetFile) {
		err := fr.Close()
		if err != nil {
			log.Fatal().Str("error", err.Error()).Msg("Failed to close the input file")
		}
	}(fr)

	// index out of range [5], please fix the schema
	pr, err := reader.NewParquetReader(fr, new(CertChain), 4)
	if err != nil {
		log.Fatal().Str("error", err.Error()).Msg("Failed to create reader")
		return nil
	}
	defer pr.ReadStop()

	// read parquet file
	num := int(pr.GetNumRows())
	//res := make([]interface{}, num)
	res, err := pr.ReadByNumber(num)
	if err != nil {
		log.Fatal().Str("error", err.Error()).Msg("Can't read")
		return nil
	}
	/*
		for i := 0; i < num; i++ {
			certChain := make([]CertChain, 1)
			if err = pr.Read(&certChain); err != nil {
				log.Fatal().Str("error", err.Error()).Msg("Can't read")
				return nil
			}
			res[i] = certChain
			break
		}
	*/
	certChains := make([]CertChain, len(res))
	for i, v := range res {
		certChains[i] = v.(CertChain)
	}
	return certChains
}
