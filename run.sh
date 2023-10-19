#!/usr/bin/env bash

INPUT_PARQUET=$1
PORT=$2
SCAN_DATE=$3
SHARED_DIR="shared_dir"

# run validator
podman run --net=host --rm -v "$(pwd)"/${SHARED_DIR}:/app/${SHARED_DIR} --name cert-validator cert-validator --input-parquet="${INPUT_PARQUET}" --scan-date="${SCAN_DATE}" --output=${SHARED_DIR}/output.parquet -v 2 --log-file=${SHARED_DIR}/log.json --rm

# upload results
podman run --net=host --rm -v "$(pwd)"/${SHARED_DIR}:/app/${SHARED_DIR} cert-validator-upload --log-file=${SHARED_DIR}/log.json --output=${SHARED_DIR}/output.parquet --port="${PORT}" --scan-date="${SCAN_DATE}"
