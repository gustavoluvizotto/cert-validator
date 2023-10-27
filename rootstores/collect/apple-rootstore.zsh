#!/usr/bin/env zsh

# https://stackoverflow.com/questions/32472337/osx-export-system-certificates-from-keychain-in-pem-format-programmatically
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > shared_dir/apple-keychain-certs.pem

go run rootstores/collect/collect.go --collect-apple
rm -f shared_dir/apple-keychain-certs.pem
