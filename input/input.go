package input

import (
	"encoding/json"
	"github.com/gustavoluvizotto/cert-validator/misc"
	"github.com/rs/zerolog/log"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/reader"
	"github.com/xitongsys/parquet-go/source"
	"strconv"
	"strings"
)

type CertChain struct {
	Id    *int32   `parquet:"name=id, type=INT32"`
	Chain []string `parquet:"name=chain, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
}

func LoadCsv(fileName string) []CertChain {
	records, err := misc.LoadCsv(fileName)
	if err != nil {
		log.Fatal().Str("error", err.Error()).Msg("Unable to load CSV file")
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
		}
		id2 := int32(id)
		certChains[i] = CertChain{
			Id:    &id2,
			Chain: pemCerts,
		}
	}

	return certChains
}

func LoadParquet(fileName string) []CertChain {
	fr, err := local.NewLocalFileReader(fileName)
	if err != nil {
		log.Fatal().Str("file", fileName).Str("error", err.Error()).Msg("Failed to open file")
	}
	defer func(fr source.ParquetFile) {
		err := fr.Close()
		if err != nil {
			log.Warn().Str("error", err.Error()).Msg("Failed to close the input file")
		}
	}(fr)

	pr, err := reader.NewParquetReader(fr, new(CertChain), 4)
	if err != nil {
		log.Fatal().Str("error", err.Error()).Msg("Failed to create reader")
	}
	defer pr.ReadStop()

	// read parquet file
	num := int(pr.GetNumRows())
	res, err := pr.ReadByNumber(num)
	if err != nil {
		log.Fatal().Str("error", err.Error()).Msg("Can't read")
	}

	certChains := make([]CertChain, len(res))
	for i, v := range res {
		certChains[i] = v.(CertChain)
	}
	return certChains
}
