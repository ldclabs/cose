# Keys, Algorithms, COSE and CWT in Go

[![CI](https://github.com/ldclabs/cose/actions/workflows/ci.yml/badge.svg)](https://github.com/ldclabs/cose/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/ldclabs/cose/branch/main/graph/badge.svg)](https://codecov.io/gh/ldclabs/cose)
[![CodeQL](https://github.com/ldclabs/cose/actions/workflows/codeql.yml/badge.svg)](https://github.com/ldclabs/cose/actions/workflows/codeql.yml)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/ldclabs/cose/main/LICENSE)
[![Installation](https://img.shields.io/badge/go-%3E%3D%201.19-blue)](#installation)
[![Go Reference](https://pkg.go.dev/badge/github.com/ldclabs/cose.svg)](https://pkg.go.dev/github.com/ldclabs/cose)

A Go library for [CBOR Object Signing and Encryption (COSE)][cose-spec] and [CBOR Web Token (CWT)][cwt-spec].

## Table of Contents

- [Keys, Algorithms, COSE and CWT in Go](#keys-algorithms-cose-and-cwt-in-go)
	- [Table of Contents](#table-of-contents)
	- [Overview](#overview)
	- [Highlights](#highlights)
	- [Installation](#installation)
	- [Quick Start](#quick-start)
	- [Package Guide](#package-guide)
	- [Examples](#examples)
	- [Development](#development)
	- [Security](#security)
	- [References](#references)
	- [License](#license)

## Overview

This project provides:

- COSE message types defined by RFC 9052: Encrypt, Encrypt0, Mac, Mac0, Sign, Sign1, Recipient, and KDF context.
- CWT claims parsing/validation utilities defined by RFC 8392.
- IANA registries and key/algorithm abstractions defined by RFC 9053.

The implementation targets interoperability, explicit algorithm selection, and practical use in constrained or binary-first environments where CBOR is preferred.

## Highlights

- Full COSE key object modeling and conversion helpers.
- Built-in support for common algorithms:
  - Signature: ECDSA, Ed25519
  - Encryption: AES-CCM, AES-GCM, ChaCha20/Poly1305
  - MAC: AES-CBC-MAC, HMAC
  - KDF: HKDF (SHA and AES variants)
  - ECDH: P-256, P-384, P-521, X25519
- Generic APIs for typed payload signing/verification and encryption/decryption.
- Rich test suite including package examples.

## Installation

```sh
go get github.com/ldclabs/cose
```

Import the packages you need:

```go
import (
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
)
```

Register algorithm implementations with side-effect imports:

```go
import (
	_ "github.com/ldclabs/cose/key/ed25519"
	_ "github.com/ldclabs/cose/key/ecdsa"
	_ "github.com/ldclabs/cose/key/aesgcm"
	_ "github.com/ldclabs/cose/key/aesccm"
	_ "github.com/ldclabs/cose/key/chacha20poly1305"
	_ "github.com/ldclabs/cose/key/hmac"
	_ "github.com/ldclabs/cose/key/aesmac"
	_ "github.com/ldclabs/cose/key/ecdh"
	_ "github.com/ldclabs/cose/key/hkdf"
)
```

## Quick Start

The snippet below creates a CWT payload, signs it with COSE_Sign1, verifies it, and validates claims:

```go
package main

import (
	"fmt"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
	"github.com/ldclabs/cose/key/ed25519"
)

func main() {
	priv, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	signer, err := priv.Signer()
	if err != nil {
		panic(err)
	}

	pub, err := ed25519.ToPublicKey(priv)
	if err != nil {
		panic(err)
	}
	verifier, err := pub.Verifier()
	if err != nil {
		panic(err)
	}

	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "ldc:chain",
		Audience:   "ldc:txpool",
		Expiration: time.Now().Add(5 * time.Minute).Unix(),
	}

	msg := cose.Sign1Message[cwt.Claims]{Payload: claims}
	encoded, err := msg.SignAndEncode(signer, nil)
	if err != nil {
		panic(err)
	}

	verified, err := cose.VerifySign1Message[cwt.Claims](verifier, encoded, nil)
	if err != nil {
		panic(err)
	}

	validator, err := cwt.NewValidator(&cwt.ValidatorOpts{
		ExpectedIssuer:   "ldc:ca",
		ExpectedAudience: "ldc:txpool",
		ClockSkew:        time.Minute,
	})
	if err != nil {
		panic(err)
	}

	if err := validator.Validate(&verified.Payload); err != nil {
		panic(err)
	}

	fmt.Println("ok")
}
```

## Package Guide

| Package                                                                                 | Import                                         | Description                                                        |
| --------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------ |
| [cose](https://pkg.go.dev/github.com/ldclabs/cose/cose)                                 | `github.com/ldclabs/cose/cose`                 | COSE message model and encode/decode/sign/encrypt APIs (RFC 9052). |
| [cwt](https://pkg.go.dev/github.com/ldclabs/cose/cwt)                                   | `github.com/ldclabs/cose/cwt`                  | CWT claims model and validation logic (RFC 8392).                  |
| [key](https://pkg.go.dev/github.com/ldclabs/cose/key)                                   | `github.com/ldclabs/cose/key`                  | COSE key objects, interfaces, registries, and CBOR helpers.        |
| [iana](https://pkg.go.dev/github.com/ldclabs/cose/iana)                                 | `github.com/ldclabs/cose/iana`                 | Constants for COSE/CWT/CBOR IANA registries.                       |
| [key/ed25519](https://pkg.go.dev/github.com/ldclabs/cose/key/ed25519)                   | `github.com/ldclabs/cose/key/ed25519`          | Ed25519 signing support.                                           |
| [key/ecdsa](https://pkg.go.dev/github.com/ldclabs/cose/key/ecdsa)                       | `github.com/ldclabs/cose/key/ecdsa`            | ECDSA signing support.                                             |
| [key/ecdh](https://pkg.go.dev/github.com/ldclabs/cose/key/ecdh)                         | `github.com/ldclabs/cose/key/ecdh`             | ECDH key agreement support.                                        |
| [key/hmac](https://pkg.go.dev/github.com/ldclabs/cose/key/hmac)                         | `github.com/ldclabs/cose/key/hmac`             | HMAC support.                                                      |
| [key/aesmac](https://pkg.go.dev/github.com/ldclabs/cose/key/aesmac)                     | `github.com/ldclabs/cose/key/aesmac`           | AES-CBC-MAC support.                                               |
| [key/aesgcm](https://pkg.go.dev/github.com/ldclabs/cose/key/aesgcm)                     | `github.com/ldclabs/cose/key/aesgcm`           | AES-GCM content encryption support.                                |
| [key/aesccm](https://pkg.go.dev/github.com/ldclabs/cose/key/aesccm)                     | `github.com/ldclabs/cose/key/aesccm`           | AES-CCM content encryption support.                                |
| [key/chacha20poly1305](https://pkg.go.dev/github.com/ldclabs/cose/key/chacha20poly1305) | `github.com/ldclabs/cose/key/chacha20poly1305` | ChaCha20/Poly1305 content encryption support.                      |
| [key/hkdf](https://pkg.go.dev/github.com/ldclabs/cose/key/hkdf)                         | `github.com/ldclabs/cose/key/hkdf`             | HKDF derivation support.                                           |

## Examples

- COSE examples: `cose/*_example_test.go`
- CWT examples: `cwt/example_test.go`
- Algorithm package examples/tests: `key/**/**/*_test.go`

Run package examples together with tests:

```sh
go test ./...
```

## Development

Project helper targets:

```sh
make test    # go test -v -failfast -tags=test --race ./...
make update  # go get -u all && go mod tidy
```

## Security

- See [SECURITY.md](SECURITY.md) for vulnerability reporting.
- Keep dependencies and toolchain updated.
- Prefer strict key operation checks (`key_ops`) and validated claim constraints in production.

## References

1. [RFC9052: CBOR Object Signing and Encryption (COSE)][cose-spec]
2. [RFC8392: CBOR Web Token (CWT)][cwt-spec]
3. [RFC9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms][algorithms-spec]
4. [IANA: CBOR Object Signing and Encryption (COSE)][iana-cose]
5. [IANA: CBOR Web Token (CWT) Claims][iana-cwt]
6. [IANA: Concise Binary Object Representation (CBOR) Tags][iana-cbor-tags]

[cbor]: https://datatracker.ietf.org/doc/html/rfc8949
[cose-spec]: https://datatracker.ietf.org/doc/html/rfc9052
[cwt-spec]: https://datatracker.ietf.org/doc/html/rfc8392
[algorithms-spec]: https://datatracker.ietf.org/doc/html/rfc9053
[iana-cose]: https://www.iana.org/assignments/cose/cose.xhtml
[iana-cwt]: https://www.iana.org/assignments/cwt/cwt.xhtml
[iana-cbor-tags]: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml

## License

Copyright © 2022-2024 [LDC Labs](https://github.com/ldclabs).

`ldclabs/cose` is licensed under the MIT License. See [LICENSE](LICENSE).