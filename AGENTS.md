# Agent Guide for `github.com/ldclabs/cose`

This repository is a Go module for COSE, CWT, COSE keys, and IANA constants.
When generating code against this module, prefer the public package APIs over
hand-built CBOR arrays or maps.

## Package Map

- `github.com/ldclabs/cose/cose`: COSE message types and encode/decode helpers.
- `github.com/ldclabs/cose/cwt`: CWT claim structs and validators.
- `github.com/ldclabs/cose/key`: COSE key model, registry, CBOR helpers, and crypto interfaces.
- `github.com/ldclabs/cose/iana`: IANA labels, algorithms, curves, operations, and tags.
- `github.com/ldclabs/cose/key/all`: opt-in aggregate import for built-in algorithm packages.

## Algorithm Registration

The `key.Key.Signer`, `Verifier`, `MACer`, and `Encryptor` methods use the
registry in `key`. Import the concrete algorithm package before calling them.
For generated applications and examples, this is the least surprising default:

```go
import _ "github.com/ldclabs/cose/key/all"
```

For library code, prefer importing only the concrete algorithms actually needed,
for example:

```go
import (
	"github.com/ldclabs/cose/key/ed25519"
	_ "github.com/ldclabs/cose/key/aesgcm"
)
```

If an error contains `is not registered`, add the matching algorithm package or
the aggregate `key/all` import. Do not work around it by bypassing the registry.

## Key Construction

Prefer the per-package `GenerateKey` constructors over hand-built key maps. They
set the correct `kty`, `crv`, `alg`, and key-bytes for you, so an agent never has
to guess IANA label combinations:

| Use case          | Constructor                                  | Algorithm argument (from `iana`)                          |
| ----------------- | -------------------------------------------- | --------------------------------------------------------- |
| EdDSA signing     | `ed25519.GenerateKey()`                      | none                                                      |
| ECDSA signing     | `ecdsa.GenerateKey(alg)`                     | `AlgorithmES256`, `AlgorithmES384`, `AlgorithmES512`      |
| ECDH agreement    | `ecdh.GenerateKey(crv)`                      | `EllipticCurveP_256/P_384/P_521`, `EllipticCurveX25519`   |
| AES-GCM encrypt   | `aesgcm.GenerateKey(alg)`                    | `AlgorithmA128GCM`, `AlgorithmA192GCM`, `AlgorithmA256GCM`|
| AES-CCM encrypt   | `aesccm.GenerateKey(alg)`                    | `AlgorithmAES_CCM_*`                                      |
| ChaCha20/Poly1305 | `chacha20poly1305.GenerateKey()`            | none                                                      |
| HMAC              | `hmac.GenerateKey(alg)`                      | `AlgorithmHMAC_256_64/256_256/384_384/512_512`           |
| AES-CBC-MAC       | `aesmac.GenerateKey(alg)`                    | `AlgorithmAES_MAC_*`                                      |

- For signing, derive the public key with `ed25519.ToPublicKey` / `ecdsa.ToPublicKey`
  before verifying; symmetric algorithms reuse the same key for both sides.
- If a key must be built from existing raw bytes (a `key.Key` literal), validate
  it with the matching package's `CheckKey` before use instead of trusting the
  map shape.

## API Selection

- Use `cose.Sign1Message[T]` for one-signer COSE_Sign1 messages.
- Use `cose.SignMessage[T]` for multi-signature COSE_Sign messages.
- Use `cose.Mac0Message[T]` for one-recipient COSE_Mac0 messages.
- Use `cose.MacMessage[T]` for COSE_Mac messages with recipients.
- Use `cose.Encrypt0Message[T]` for direct content encryption.
- Use `cose.EncryptMessage[T]` when the message carries COSE recipients.
- Use `cwt.Claims` for the common registered claims.
- Use `cwt.ClaimsMap` when custom CWT claims are needed.
- Use the `Detached` helpers when the payload or ciphertext is transported
  separately from the COSE structure.

Prefer the high-level helpers such as `SignAndEncode`,
`VerifySign1Message`, `EncryptAndEncode`, and `DecryptEncrypt0Message` for new
code. Use `MarshalCBOR` / `UnmarshalCBOR` directly only when a workflow needs a
separate decode, validation, or detached-content step.

## COSE Header Rules

- Put `alg`, `crit`, IV, and partial IV parameters in the correct protected or
  unprotected bucket as required by the COSE RFCs and this package's decoders.
- Do not put the same label in both protected and unprotected headers.
- If `crit` is present, it must be a non-empty protected-header array, and each
  critical label must also be present in the protected bucket.
- Keep `externalData` byte-for-byte identical between sign/verify,
  MAC/verify, and encrypt/decrypt calls. `nil` and an empty byte slice are both
  valid, but callers should pass one convention consistently.

## Payload and Key Rules

- Typed payload APIs encode non-`[]byte` payloads as CBOR through `key.MarshalCBOR`.
- `[]byte` payloads are treated as the raw payload bytes.
- Use `key.MarshalCBOR`, `key.UnmarshalCBOR`, and package-specific constructors
  such as `ed25519.GenerateKey`, `aesgcm.GenerateKey`, and `hmac.GenerateKey`.
- Respect `key_ops` when present; do not strip it to make an operation pass.
- Use public-key conversion helpers such as `ed25519.ToPublicKey` before
  verification when starting from a private key.

## Examples and Verification

Runnable recipes live in `examples/`:

- `go run ./examples/sign1-cwt`
- `go run ./examples/encrypt0-cwt`
- `go run ./examples/detached-sign1`

Before finishing changes, run:

```sh
gofmt -w <changed .go files>
go test ./...
```

Use the package example tests in `cose/*_example_test.go` and
`cwt/example_test.go` as source-backed references for generated snippets.
