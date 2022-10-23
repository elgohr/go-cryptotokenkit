# Golang-CryptoTokenKit

[![Test](https://github.com/elgohr/golang-cryptotokenkit/workflows/Test/badge.svg)](https://github.com/elgohr/golang-cryptotokenkit/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/elgohr/golang-cryptotokenkit)](https://goreportcard.com/report/github.com/elgohr/golang-cryptotokenkit)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/elgohr/golang-cryptotokenkit)](https://pkg.go.dev/github.com/elgohr/golang-cryptotokenkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Golang-CryptoTokenKit is a [CryptoTokenKit](https://developer.apple.com/documentation/cryptotokenkit)-Wrapper for working with cryptographic assets on the Mac in Go.

# Install
```
go get github.com/elgohr/golang-cryptotokenkit
```

# Credits
This repository is highly inspired by [smimesign](https://github.com/github/smimesign/blob/main/certstore/certstore_darwin.go).  
Nevertheless it's updated to latest CoreFoundation calls and extended by additional methods, that are not needed for smimesign.