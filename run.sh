#!/usr/bin/env bash

SHARED_DIR="shared_dir"

declare -a PARAMS=()
while (( "$#" )); do
    if [ -n "$1" ]; then
        PARAMS+=("$1")
    fi
done

# show to the user to run it...
echo "podman run --net=host --rm -v \"\$(pwd)\"/${SHARED_DIR}:/app/${SHARED_DIR} --name cert-validator cert-validator"

