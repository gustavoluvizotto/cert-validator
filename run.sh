#!/usr/bin/env bash

podman run --rm -v "$(pwd)":/go/bin --name cert-validator cert-validator "$@"
