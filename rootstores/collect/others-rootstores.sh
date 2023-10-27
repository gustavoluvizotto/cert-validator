#!/usr/bin/env bash

SHARED_DIR="shared_dir"

# retrieve all others root store files
podman run --net=host --rm -v "$(pwd)"/${SHARED_DIR}:/app/${SHARED_DIR} rootstores-collect --collect-others
