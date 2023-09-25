#!/usr/bin/env bash

SHARED_DIR="shared_dir"

podman run --rm -v "$(pwd)"/"${SHARED_DIR}":/go/"${SHARED_DIR}" --name cert-validator cert-validator "$@"

