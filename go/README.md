COSE, CWT and crypto Keys for Go
-------------------------

*A multi-language, cross-platform library for the [CBOR Object Signing and Encryption (COSE)][cose-spec] and [CBOR Web Token (CWT)][cwt-spec].*

## Index

- [COSE, CWT and crypto Keys for Go](#cose-cwt-and-crypto-keys-for-go)
- [Index](#index)
- [Introduction](#introduction)
- [Installation](#installation)
- [Examples](#examples)
	- [Create a simple CWT with one signer](#create-a-simple-cwt-with-one-signer)
	- [Create a rich CWT with two signers](#create-a-rich-cwt-with-two-signers)
- [Reference](#reference)

## Introduction

COSE is a standard for signing and encrypting data in the [CBOR][cbor] data format. It is designed to be simple and efficient, and to be usable in constrained environments. It is intended to be used in a variety of applications, including the Internet of Things, and is designed to be extensible to support new algorithms and applications.

## Installation

To install COSE locally run:

```sh
go get github.com/ldclabs/cose/go/...
```

To import in the cwt package:

```go
import "github.com/ldclabs/cose/go/cwt"
```

To import in the cose package:

```go
import "github.com/ldclabs/cose/go/cose"
```

To import in the key package:

```go
import "github.com/ldclabs/cose/go/key"
```

To register crypto algorithms:

```go
import (
  _ "github.com/ldclabs/cose/go/key/ecdsa"
  _ "github.com/ldclabs/cose/go/key/ed25519"
  _ "github.com/ldclabs/cose/go/key/hmac"
)
```

## Examples

### Create a simple CWT with one signer

```go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ldclabs/cose/go/cwt"
	"github.com/ldclabs/cose/go/key/ed25519"
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

	// Create a set of claims
	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "ldc:chain",
		Audience:   "ldc:txpool",
		Expiration: 1670123579,
		CWTID:      []byte{1, 2, 3, 4},
	}

	// Sign the claims
	cwtData, err := claims.Sign1AndEncode(signer, nil)
	if err != nil {
		panic(err)
	}

	// Verify the claims
	myClaims, err := cwt.Verify1AndDecode(verifier, cwtData, nil)
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

	// Validate the claims
	err = validator.Validate(myClaims)
	fmt.Printf("%v\n", err)
	// cose/go/cwt: Validator.Validate: token has expired

	cborData := myClaims.Bytesify()
	fmt.Printf("CBOR(%d bytes): %x\n", len(cborData), cborData)
	// CBOR(44 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b074401020304

	jsonData, err := json.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("JSON(%d bytes): %s\n", len(jsonData), string(jsonData))
	// JSON(87 bytes): {"iss":"ldc:ca","sub":"ldc:chain","aud":"ldc:txpool","exp":1670123579,"cti":"01020304"}
}
```

### Create a rich CWT with two signers

```go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ldclabs/cose/go/cwt"
	"github.com/ldclabs/cose/go/key"
	"github.com/ldclabs/cose/go/key/ecdsa"
	"github.com/ldclabs/cose/go/key/ed25519"
)

func main() {
	// Create a ed25519 signer key
	privKey1, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	privKey2, err := ecdsa.GenerateKey(key.AlgES256)
	if err != nil {
		panic(err)
	}
	ks := key.KeySet{privKey1, privKey2}

	// Create a set of claims
	claims := cwt.ClaimsMap{
		cwt.KeyIss:    "ldc:ca",
		cwt.KeySub:    "ldc:chain",
		cwt.KeyAud:    "ldc:txpool",
		cwt.KeyExp:    1670123579,
		key.IntKey(9): "read,write", // The scope of an access token, https://www.iana.org/assignments/cwt/cwt.xhtml.
	}

	// Sign the claims
	signers, err := ks.Signers()
	if err != nil {
		panic(err)
	}
	cwtData, err := claims.SignAndEncode(signers, nil)
	if err != nil {
		panic(err)
	}

	// Verify the claims
	verifiers, err := ks.Verifiers()
	if err != nil {
		panic(err)
	}
	myClaims, err := cwt.VerifyAndDecodeMap(verifiers, cwtData, nil)
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

	err = validator.ValidateMap(myClaims)
	fmt.Printf("%v\n", err)
	// cose/go/cwt: Validator.Validate: token has expired

	cborData, err := key.MarshalCBOR(myClaims)
	// cborData, err := cbor.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CBOR(%d bytes): %x\n", len(cborData), cborData)
	// CBOR(50 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b096a726561642c7772697465

	jsonData, err := json.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("JSON(%d bytes): %s\n", len(jsonData), string(jsonData))
	// JSON(79 bytes): {"1":"ldc:ca","2":"ldc:chain","3":"ldc:txpool","4":1670123579,"9":"read,write"}
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
