// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new key for Ed25519.
func GenerateKey() (key.Key, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/ed25519: GenerateKey: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[int]any{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKid:    key.SumKid(pubKey), // default kid, can be set to other value.
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519, // REQUIRED
		iana.OKPKeyParameterD:   privKey.Seed(),            // REQUIRED
	}, nil
}

// KeyFromSeed returns a private Key with given ed25519.PrivateKey seed.
func KeyFromSeed(seed []byte) (key.Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf(`cose/go/key/ed25519: KeyFromSeed: invalid ed25519 seed size, expected %d, got %d`,
			ed25519.SeedSize, len(seed))
	}

	return KeyFromPrivate(ed25519.NewKeyFromSeed(seed))
}

// KeyFromPrivate returns a private Key with given ed25519.PrivateKey.
func KeyFromPrivate(pk ed25519.PrivateKey) (key.Key, error) {
	if ed25519.PrivateKeySize != len(pk) {
		return nil, fmt.Errorf(`cose/go/key/ed25519: KeyFromPrivate: invalid ed25519.PrivateKey size, expected %d, got %d`,
			ed25519.PrivateKeySize, len(pk))
	}

	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[int]any{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKid:    key.SumKid(pk.Public().(ed25519.PublicKey)), // default kid, can be set to other value.
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519, // REQUIRED
		iana.OKPKeyParameterD:   pk.Seed(),                 // REQUIRED
	}, nil
}

// KeyToPrivate returns the private key from the given key.
func KeyToPrivate(k key.Key) (ed25519.PrivateKey, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(iana.OKPKeyParameterD) {
		return nil, fmt.Errorf("cose/go/key/ed25519: KeyToPrivate: invalid key")
	}

	d, _ := k.GetBytes(iana.OKPKeyParameterD)
	privKey := ed25519.NewKeyFromSeed(d)

	x, _ := k.GetBytes(iana.OKPKeyParameterX)
	if k.Has(iana.OKPKeyParameterX) {
		if !bytes.Equal(privKey.Public().([]byte), x) {
			return nil, fmt.Errorf("cose/go/key/ed25519: KeyToPrivate: invalid parameters x")
		}
	}
	return privKey, nil
}

// KeyFromPublic returns a public Key with given ed25519.PublicKey.
func KeyFromPublic(pk ed25519.PublicKey) (key.Key, error) {
	if ed25519.PublicKeySize != len(pk) {
		return nil, fmt.Errorf(`cose/go/key/ed25519: KeyFromPublic: invalid ed25519.PublicKey size, expected %d, got %d`,
			ed25519.PublicKeySize, len(pk))
	}

	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[int]any{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKid:    key.SumKid(pk), // default kid, can be set to other value.
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519, // REQUIRED
		iana.OKPKeyParameterX:   pk,                        // REQUIRED
	}, nil
}

// KeyToPublic returns the public key from the given key.
func KeyToPublic(k key.Key) (ed25519.PublicKey, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(iana.OKPKeyParameterX) {
		return nil, fmt.Errorf("cose/go/key/ed25519: KeyToPublic: invalid key")
	}

	x, _ := k.GetBytes(iana.OKPKeyParameterX)
	return ed25519.PublicKey(x), nil
}

// CheckKey checks whether the given key is a valid Ed25519 key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeOKP {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid key type, expected "OKP", got %d`, k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.OKPKeyParameterCrv,
			iana.OKPKeyParameterX, iana.OKPKeyParameterD:
			// continue

		case iana.KeyParameterAlg: // optional
			if k.Alg() != iana.AlgorithmEdDSA {
				return fmt.Errorf(`cose/go/key/ed25519: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationSign, iana.KeyOperationVerify:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/ed25519: CheckKey: redundant parameter %d`, p)
		}
	}

	// RECOMMENDED
	if k.Has(iana.KeyParameterKid) {
		if x, err := k.GetBytes(iana.KeyParameterKid); err != nil || len(x) == 0 {
			return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter kid`)
		}
	}

	// REQUIRED
	if cc, err := k.GetInt(iana.OKPKeyParameterCrv); err != nil || cc != int(iana.EllipticCurveEd25519) {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter crv %d`, cc)
	}

	// REQUIRED for private key
	hasD := k.Has(iana.OKPKeyParameterD)
	d, _ := k.GetBytes(iana.OKPKeyParameterD)
	if hasD && len(d) != ed25519.SeedSize {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter d`)
	}

	// REQUIRED for public key
	// RECOMMENDED for private key
	hasX := k.Has(iana.OKPKeyParameterX)
	x, _ := k.GetBytes(iana.OKPKeyParameterX)
	if hasX && len(x) != ed25519.PublicKeySize {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter x`)
	}

	ops := k.Ops()
	switch {
	case !hasD && !hasX:
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: missing parameter x or d`)

	case hasD && !ops.EmptyOrHas(iana.KeyOperationSign):
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: don't include "sign"`)

	case !hasD && !ops.EmptyOrHas(iana.KeyOperationVerify):
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: don't include "verify"`)
	}

	return nil
}

// ToPublicKey converts the given private key to a public key.
// If the key is already a public key, it is returned as-is.
func ToPublicKey(k key.Key) (key.Key, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(iana.OKPKeyParameterD) {
		if !k.Has(iana.OKPKeyParameterX) {
			return nil, errors.New(`cose/go/key/ed25519: ToPublicKey: missing parameter x`)
		}
		return k, nil
	}

	d, _ := k.GetBytes(iana.OKPKeyParameterD)
	pk := map[int]any{
		iana.KeyParameterKty:    k.Kty(),
		iana.OKPKeyParameterCrv: k[iana.OKPKeyParameterCrv],
	}

	if v, ok := k[iana.KeyParameterKid]; ok {
		pk[iana.KeyParameterKid] = v
	}

	if v, ok := k[iana.KeyParameterAlg]; ok {
		pk[iana.KeyParameterAlg] = v
	}

	if _, ok := k[iana.KeyParameterKeyOps]; ok {
		pk[iana.KeyParameterKeyOps] = key.Ops{iana.KeyOperationVerify}
	}

	privKey := ed25519.NewKeyFromSeed(d)
	pk[iana.OKPKeyParameterX] = privKey.Public()
	return pk, nil
}

type ed25519Signer struct {
	key     key.Key
	privKey ed25519.PrivateKey
}

// NewSigner creates a key.Signer for the given private key.
func NewSigner(k key.Key) (key.Signer, error) {
	privKey, err := KeyToPrivate(k)
	if err != nil {
		return nil, err
	}

	return &ed25519Signer{key: k, privKey: privKey}, nil
}

// Sign implements the key.Signer interface.
// Sign computes the digital signature for data.
func (e *ed25519Signer) Sign(data []byte) ([]byte, error) {
	if !e.key.Ops().EmptyOrHas(iana.KeyOperationSign) {
		return nil, fmt.Errorf("cose/go/key/ed25519: Sign: invalid key_ops")
	}

	return ed25519.Sign(e.privKey, data), nil
}

// Key implements the key.Signer interface.
// Key returns the private key in Signer.
func (e *ed25519Signer) Key() key.Key {
	return e.key
}

type ed25519Verifier struct {
	key    key.Key
	pubKey ed25519.PublicKey
}

// NewVerifier creates a key.Verifier for the given public key.
func NewVerifier(k key.Key) (key.Verifier, error) {
	pk, err := ToPublicKey(k)
	if err != nil {
		return nil, err
	}

	x, _ := pk.GetBytes(iana.OKPKeyParameterX)
	return &ed25519Verifier{key: pk, pubKey: ed25519.PublicKey(x)}, nil
}

// Verify implements the key.Verifier interface.
// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
func (e *ed25519Verifier) Verify(data, sig []byte) error {
	if !e.key.Ops().EmptyOrHas(iana.KeyOperationVerify) {
		return fmt.Errorf("cose/go/key/ed25519: Verify: invalid key_ops")
	}

	if !ed25519.Verify(e.pubKey, data, sig) {
		return fmt.Errorf("cose/go/key/ed25519: Verify: invalid signature")
	}

	return nil
}

// Key implements the key.Verifier interface.
// Key returns the public key in Verifier.
func (e *ed25519Verifier) Key() key.Key {
	return e.key
}