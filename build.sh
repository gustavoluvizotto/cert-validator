#!/usr/bin/env bash

podman build -f=Dockerfile -t cert-validator .
podman build -f=Dockerfile.upload -t upload .
