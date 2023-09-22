package result

import (
	"github.com/rs/zerolog/log"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/source"
	"github.com/xitongsys/parquet-go/writer"
)

type ValidationResult struct {
	Id      int32  `parquet:"name=id, type=INT32"`
	IsValid bool   `parquet:"name=is_valid, type=BOOLEAN"`
	Error   string `parquet:"name=error, type=BYTE_ARRAY, convertedtype=UTF8"`
}

func StoreResult(result []ValidationResult, fileName string) {
	// write []ValidationResult to parquet file
	fw, err := local.NewLocalFileWriter(fileName)
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Can't create file")
		return
	}
	defer func(fw source.ParquetFile) {
		err := fw.Close()
		if err != nil {
			log.Fatal().Str("error", err.Error()).Msg("Failed to close the output file")
		}
	}(fw)

	pw, err := writer.NewParquetWriter(fw, new(ValidationResult), 4)
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Can't create parquet writer")
		return
	}
	for _, stu := range result {
		if err = pw.Write(stu); err != nil {
			log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Write error")
			return
		}
	}

	if err = pw.WriteStop(); err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("WriteStop error")
	}

}
