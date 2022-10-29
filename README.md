# Golang-CryptoTokenKit

[![Test](https://github.com/elgohr/go-cryptotokenkit/workflows/Test/badge.svg)](https://github.com/elgohr/go-cryptotokenkit/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/elgohr/go-cryptotokenkit)](https://goreportcard.com/report/github.com/elgohr/go-cryptotokenkit)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/elgohr/go-cryptotokenkit)](https://pkg.go.dev/github.com/elgohr/go-cryptotokenkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Golang-CryptoTokenKit is a [CryptoTokenKit](https://developer.apple.com/documentation/cryptotokenkit)-Wrapper for working with cryptographic assets on the Mac in Go.

# Install
```
go get github.com/elgohr/go-cryptotokenkit
```

# Credits
This repository is highly inspired by [smimesign](https://github.com/github/smimesign/blob/main/certstore/certstore_darwin.go).  
Nevertheless it's updated to latest CoreFoundation calls and extended by additional methods, that are not needed for smimesign.