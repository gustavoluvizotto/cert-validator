#!/usr/bin/env bash

SHARED_DIR="shared_dir"

declare -a PARAMS=()
while (( "$#" )); do
    if [ -n "$1" ]; then
        PARAMS+=("$1")
    fi
done

podman run --rm -v "$(pwd)"/"${SHARED_DIR}":/go/"${SHARED_DIR}" --name cert-validator cert-validator "${PARAMS[@]}"

