package misc

import (
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"os"
)

func LoadCsv(fileName string) ([][]string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to read input file")
		return nil, err
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
		return nil, err
	}
	// read all records
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal().Str("fileName", fileName).Str("error", err.Error()).Msg("Unable to parse CSV file")
		return nil, err
	}

	return records, nil
}
