COSE, CWT, Keys and Algorithms
-------------------------
[![CI](https://github.com/ldclabs/cose/actions/workflows/ci-cover.yml/badge.svg)](https://github.com/ldclabs/cose/actions?query=workflow%3Aci-cover)
[![Codecov](https://codecov.io/gh/ldclabs/cose/branch/main/graph/badge.svg)](https://codecov.io/gh/ldclabs/cose)
[![Go Reference](https://pkg.go.dev/badge/github.com/ldclabs/cose.svg)](https://pkg.go.dev/github.com/ldclabs/cose)

*A golang library for the [CBOR Object Signing and Encryption (COSE)][cose-spec] and [CBOR Web Token (CWT)][cwt-spec].*

## Index

- [COSE, CWT, Keys and Algorithms](#cose-cwt-keys-and-algorithms)
- [Index](#index)
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Packages](#packages)
- [Examples](#examples)
	- [Create a simple CWT with a signer](#create-a-simple-cwt-with-a-signer)
	- [Create a complex CWT with one more signers](#create-a-complex-cwt-with-one-more-signers)
- [Reference](#reference)

## Introduction

COSE is a standard for signing and encrypting data in the [CBOR][cbor] data format. It is designed to be simple and efficient, and to be usable in constrained environments. It is intended to be used in a variety of applications, including the Internet of Things, and is designed to be extensible to support new algorithms and applications.

## Features

* CWT: Full support;
* COSE: COSE_Encrypt, COSE_Encrypt0, COSE_Mac, COSE_Mac0, COSE_Sign, COSE_Sign1;
* Algorithms:
  - Signing: ECDSA, Ed25519
  - Encryption: AES-CCM, AES-GCM, ChaCha20/Poly1305
  - MAC: AES-MAC, HMAC
  - KDF: HKDF-SHA, HKDF-AES

## Installation

To install COSE locally run:

```sh
go get github.com/ldclabs/cose/...
```

To import in the cwt package:

```go
import "github.com/ldclabs/cose/cwt"
```

To register crypto algorithms:

```go
import (
  _ "github.com/ldclabs/cose/key/ed25519"
  _ "github.com/ldclabs/cose/key/aesgcm"
)
```

## Packages

| Package name                                           | Import                         | Description                    |
|--------------------------------------------------------|--------------------------------|--------------------------------|
| [cose](https://pkg.go.dev/github.com/ldclabs/cose/cose) | github.com/ldclabs/cose/cose | [RFC9052: CBOR Object Signing and Encryption][cose-spec] |
| [cwt](https://pkg.go.dev/github.com/ldclabs/cose/cwt) | github.com/ldclabs/cose/cwt | [RFC8392: CBOR Web Token][cwt-spec] |
| [iana](https://pkg.go.dev/github.com/ldclabs/cose/iana) | github.com/ldclabs/cose/iana | [IANA: COSE][iana-cose] + [IANA: CWT][iana-cwt] + [IANA: CBOR Tags][iana-cbor-tags]|
| [key](https://pkg.go.dev/github.com/ldclabs/cose/key) | github.com/ldclabs/cose/key | [RFC9053: Algorithms and Key Objects][algorithms-spec] |
| [ed25519](https://pkg.go.dev/github.com/ldclabs/cose/key/ed25519) | github.com/ldclabs/cose/key/ed25519 | Signature Algorithm: [Ed25519](https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa) |
| [ecdsa](https://pkg.go.dev/github.com/ldclabs/cose/key/ecdsa) | github.com/ldclabs/cose/key/ecdsa | Signature Algorithm: [ECDSA](https://datatracker.ietf.org/doc/html/rfc9053#name-ecdsa) |
| [hmac](https://pkg.go.dev/github.com/ldclabs/cose/key/hmac) | github.com/ldclabs/cose/key/hmac | Message Authentication Code (MAC) Algorithm: [HMAC](https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti) |
| [aesmac](https://pkg.go.dev/github.com/ldclabs/cose/key/aesmac) | github.com/ldclabs/cose/key/aesmac | Message Authentication Code (MAC) Algorithm: [AES-CBC-MAC](https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti) |
| [aesgcm](https://pkg.go.dev/github.com/ldclabs/cose/key/aesgcm) | github.com/ldclabs/cose/key/aesgcm | Content Encryption Algorithm: [AES-GCM](https://datatracker.ietf.org/doc/html/rfc9053#name-aes-gcm) |
| [aesccm](https://pkg.go.dev/github.com/ldclabs/cose/key/aesccm) | github.com/ldclabs/cose/key/aesccm | Content Encryption Algorithm: [AES-CCM](https://datatracker.ietf.org/doc/html/rfc9053#name-aes-ccm) |
| [chacha20poly1305](https://pkg.go.dev/github.com/ldclabs/cose/key/chacha20poly1305) | github.com/ldclabs/cose/key/chacha20poly1305 | Content Encryption Algorithm: [ChaCha20/Poly1305](https://datatracker.ietf.org/doc/html/rfc9053#name-chacha20-and-poly1305) |
| [hkdf](https://pkg.go.dev/github.com/ldclabs/cose/key/hkdf) | github.com/ldclabs/cose/key/hkdf | Key Derivation Functions (KDFs) Algorithm: [HKDF](https://datatracker.ietf.org/doc/html/rfc9053#name-key-derivation-functions-kd) |

## Examples

### Create a simple CWT with a signer

```go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
	"github.com/ldclabs/cose/key/ed25519"
)

func main() {
	// Create a ed25519 signer key
	privKey, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	signer, err := privKey.Signer()
	if err != nil {
		panic(err)
	}

	// Create a verifier key
	pubKey, err := ed25519.ToPublicKey(privKey)
	if err != nil {
		panic(err)
	}
	verifier, err := pubKey.Verifier()
	if err != nil {
		panic(err)
	}

	// create a claims set
	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "ldc:chain",
		Audience:   "ldc:txpool",
		Expiration: 1670123579,
		CWTID:      []byte{1, 2, 3, 4},
	}

	// sign with Sign1Message
	obj := cose.Sign1Message[cwt.Claims]{Payload: claims}
	cwtData, err := obj.SignAndEncode(signer, nil)
	if err != nil {
		panic(err)
	}

	// decode and verify the cwt
	obj2, err := cose.VerifySign1Message[cwt.Claims](verifier, cwtData, nil)
	if err != nil {
		panic(err)
	}

	// validate the cwt's claims
	validator, err := cwt.NewValidator(&cwt.ValidatorOpts{
		ExpectedIssuer:   "ldc:ca",
		ExpectedAudience: "ldc:txpool",
		ClockSkew:        time.Minute,
	})
	if err != nil {
		panic(err)
	}

	err = validator.Validate(&obj2.Payload)
	fmt.Printf("Validate Claims: %v\n", err)
	// Validate Claims: cose/go/cwt: Validator.Validate: token has expired

	cborData, err := key.MarshalCBOR(obj2.Payload)
	// cborData, err := cbor.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CBOR(%d bytes): %x\n", len(cborData), cborData)
	// CBOR(44 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b074401020304
}
```

### Create a complex CWT with one more signers

```go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/ed25519"
)

func main() {
	// Create a ed25519 signer key
	privKey1, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	privKey2, err := ecdsa.GenerateKey(iana.AlgorithmES256)
	if err != nil {
		panic(err)
	}
	ks := key.KeySet{privKey1, privKey2}

	// create a claims set
	claims := cwt.ClaimsMap{
		iana.CWTClaimIss:   "ldc:ca",
		iana.CWTClaimSub:   "ldc:chain",
		iana.CWTClaimAud:   "ldc:txpool",
		iana.CWTClaimExp:   1670123579,
		iana.CWTClaimScope: "read,write",
		// and more claims...
	}

	// Sign the claims
	signers, err := ks.Signers()
	if err != nil {
		panic(err)
	}
	// sign with SignMessage
	obj := cose.SignMessage[cwt.ClaimsMap]{Payload: claims}
	cwtData, err := obj.SignAndEncode(signers, nil)
	if err != nil {
		panic(err)
	}

	// decode and verify the cwt
	verifiers, err := ks.Verifiers()
	if err != nil {
		panic(err)
	}
	obj2, err := cose.VerifySignMessage[cwt.ClaimsMap](verifiers, cwtData, nil)
	if err != nil {
		panic(err)
	}

	// Validate the claims
	validator, err := cwt.NewValidator(&cwt.ValidatorOpts{
		ExpectedIssuer:   "ldc:ca",
		ExpectedAudience: "ldc:txpool",
		ClockSkew:        time.Minute,
	})
	if err != nil {
		panic(err)
	}

	err = validator.ValidateMap(obj2.Payload)
	fmt.Printf("Validate Claims: %v\n", err)
	// Validate Claims: cose/go/cwt: Validator.Validate: token has expired

	cborData, err := key.MarshalCBOR(obj2.Payload)
	// cborData, err := cbor.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CBOR(%d bytes): %x\n", len(cborData), cborData)
	// CBOR(50 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b096a726561642c7772697465
}
```

## Reference

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
