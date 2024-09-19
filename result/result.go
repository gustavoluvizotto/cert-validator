package result

import (
	"github.com/rs/zerolog/log"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/source"
	"github.com/xitongsys/parquet-go/writer"
)

type RootStoreResult struct {
	Error       string `parquet:"name=root_store_error, type=BYTE_ARRAY, convertedtype=UTF8"`
	IsValid     bool   `parquet:"name=is_valid, type=BOOLEAN"`
	ValidChains string `parquet:"name=valid_chains, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type ValidationResult struct {
	Id                int32                      `parquet:"name=id, type=INT32"`
	Error             string                     `parquet:"name=generic_error, type=BYTE_ARRAY, convertedtype=UTF8"`
	RootStores        map[string]RootStoreResult `parquet:"name=root_stores, type=MAP, keytype=BYTE_ARRAY, keyconvertedtype=UTF8"`
	LeafCertIndex     int32                      `parquet:"name=leaf_cert_index, type=INT32"`
	AllValidLeafIndex []int32                    `parquet:"name=all_valid_leaves_index, type=LIST, valuetype=INT32"`
}

func ConsumeResultChannel(resultChan chan ValidationResult, nrChains int, fileName string) {
	if resultChan == nil {
		log.Error().Msg("Result channel is nil")
		return
	}

	var validChains []ValidationResult
	for i := 0; i < nrChains; i++ {
		validChains = append(validChains, <-resultChan)
	}

	storeResult(validChains, fileName)
}

func storeResult(result []ValidationResult, fileName string) {
	// write []ValidationResult to parquet file
	fw, err := local.NewLocalFileWriter(fileName)
	if err != nil {
		log.Error().Str("fileName", fileName).Str("error", err.Error()).Msg("Can't create file")
		return
	}
	defer func(fw source.ParquetFile) {
		err := fw.Close()
		if err != nil {
			log.Warn().Str("error", err.Error()).Msg("Failed to close the output file")
		}
	}(fw)

	pw, err := writer.NewParquetWriter(fw, new(ValidationResult), 4)
	if err != nil {
		log.Error().Str("fileName", fileName).Str("error", err.Error()).Msg("Can't create parquet writer")
		return
	}
	for _, stu := range result {
		if err = pw.Write(stu); err != nil {
			log.Warn().Str("fileName", fileName).Str("error", err.Error()).Msg("Write error")
			return
		}
	}

	if err = pw.WriteStop(); err != nil {
		log.Warn().Str("fileName", fileName).Str("error", err.Error()).Msg("WriteStop error")
	}

}
