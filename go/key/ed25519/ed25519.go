// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"bytes"
	goed25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new key for Ed25519.
func GenerateKey() (key.Key, error) {
	pubKey, privKey, err := goed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/ed25519: GenerateKey: %w", err)
	}

	idhash := sha1.New()
	idhash.Write(pubKey)
	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[key.IntKey]any{
		key.ParamKty: key.KtyOKP,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: key.AlgEdDSA,
		key.ParamCrv: key.CrvEd25519, // REQUIRED
		key.ParamD:   privKey.Seed(), // REQUIRED
	}, nil
}

// KeyFromPrivate returns a private Key with given ed25519.PrivateKey.
func KeyFromPrivate(pk goed25519.PrivateKey) (key.Key, error) {
	if goed25519.PrivateKeySize != len(pk) {
		return nil, fmt.Errorf(`cose/go/key/ed25519: PrivKeyFromSeed: invalid ed25519..PublicKey size, expected %d, got %d`,
			goed25519.PrivateKeySize, len(pk))
	}

	pubKey := pk.Public().(goed25519.PublicKey)

	idhash := sha1.New()
	idhash.Write(pubKey)
	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[key.IntKey]any{
		key.ParamKty: key.KtyOKP,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: key.AlgEdDSA,
		key.ParamCrv: key.CrvEd25519, // REQUIRED
		key.ParamD:   pk.Seed(),      // REQUIRED
	}, nil
}

// KeyFromPublic returns a public Key with given ed25519.PublicKey.
func KeyFromPublic(pk goed25519.PublicKey) (key.Key, error) {
	if goed25519.PublicKeySize != len(pk) {
		return nil, fmt.Errorf(`cose/go/key/ed25519: KeyFromPub: invalid ed25519.PublicKey size, expected %d, got %d`,
			goed25519.PublicKeySize, len(pk))
	}

	idhash := sha1.New()
	idhash.Write(pk)
	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[key.IntKey]any{
		key.ParamKty: key.KtyOKP,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: key.AlgEdDSA,
		key.ParamCrv: key.CrvEd25519, // REQUIRED
		key.ParamX:   pk,             // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid Ed25519 key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtyOKP {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid key type, expected "OKP", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamCrv, key.ParamX, key.ParamD:
			// continue

		case key.ParamAlg: // optional
			if k.Alg() != key.AlgEdDSA {
				return fmt.Errorf(`cose/go/key/ed25519: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpSign, key.OpVerify:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/ed25519: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// RECOMMENDED
	if k.Has(key.ParamKid) {
		if x, err := k.GetBytes(key.ParamKid); err != nil || len(x) == 0 {
			return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter kid`)
		}
	}

	// REQUIRED
	if cc, err := k.GetSmallInt(key.ParamCrv); err != nil || cc != int(key.CrvEd25519) {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter crv %q`, key.Crv(cc).String())
	}

	// REQUIRED for private key
	hasD := k.Has(key.ParamD)
	d, _ := k.GetBytes(key.ParamD)
	if hasD && len(d) != goed25519.SeedSize {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter d`)
	}

	// REQUIRED for public key
	// RECOMMENDED for private key
	hasX := k.Has(key.ParamX)
	x, _ := k.GetBytes(key.ParamX)
	if hasX && len(x) != goed25519.PublicKeySize {
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: invalid parameter x`)
	}

	ops := k.Ops()
	switch {
	case !hasD && !hasX:
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: missing parameter x or d`)

	case hasD && !ops.EmptyOrHas(key.OpSign):
		return fmt.Errorf(`cose/go/key/ed25519: CheckKey: don't include "sign"`)

	case !hasD && !ops.EmptyOrHas(key.OpVerify):
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

	if !k.Has(key.ParamD) {
		if !k.Has(key.ParamX) {
			return nil, errors.New(`cose/go/key/ed25519: ToPublicKey: missing parameter x`)
		}
		return k, nil
	}

	d, _ := k.GetBytes(key.ParamD)
	pk := map[key.IntKey]any{
		key.ParamKty: k.Kty(),
		key.ParamCrv: k[key.ParamCrv],
	}

	if v, ok := k[key.ParamKid]; ok {
		pk[key.ParamKid] = v
	}

	if v, ok := k[key.ParamAlg]; ok {
		pk[key.ParamAlg] = v
	}

	if _, ok := k[key.ParamOps]; ok {
		pk[key.ParamOps] = key.Ops{key.OpVerify}
	}

	privKey := goed25519.NewKeyFromSeed(d)
	pk[key.ParamX] = privKey.Public()
	return pk, nil
}

type ed25519Signer struct {
	key     key.Key
	privKey goed25519.PrivateKey
}

// NewSigner creates a key.Signer for the given private key.
func NewSigner(k key.Key) (key.Signer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(key.ParamD) {
		return nil, fmt.Errorf("cose/go/key/ed25519: NewSigner: invalid key")
	}

	d, _ := k.GetBytes(key.ParamD)
	privKey := goed25519.NewKeyFromSeed(d)

	x, _ := k.GetBytes(key.ParamX)
	if k.Has(key.ParamX) {
		if !bytes.Equal(privKey.Public().([]byte), x) {
			return nil, fmt.Errorf("cose/go/key/ed25519: NewSigner: invalid parameters x")
		}
	}

	return &ed25519Signer{key: k, privKey: privKey}, nil
}

// Sign implements the key.Signer interface.
// Sign computes the digital signature for data.
func (e *ed25519Signer) Sign(data []byte) ([]byte, error) {
	return goed25519.Sign(e.privKey, data), nil
}

// Key implements the key.Signer interface.
// Key returns the private key in Signer.
func (e *ed25519Signer) Key() key.Key {
	return e.key
}

type ed25519Verifier struct {
	key    key.Key
	pubKey goed25519.PublicKey
}

// NewVerifier creates a key.Verifier for the given public key.
func NewVerifier(k key.Key) (key.Verifier, error) {
	pk, err := ToPublicKey(k)
	if err != nil {
		return nil, err
	}

	x, _ := pk.GetBytes(key.ParamX)
	return &ed25519Verifier{key: pk, pubKey: goed25519.PublicKey(x)}, nil
}

// Verify implements the key.Verifier interface.
// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
func (e *ed25519Verifier) Verify(data, sig []byte) error {
	if !goed25519.Verify(e.pubKey, data, sig) {
		return fmt.Errorf("cose/go/key/ed25519: Verify: invalid signature")
	}

	return nil
}

// Key implements the key.Verifier interface.
// Key returns the public key in Verifier.
func (e *ed25519Verifier) Key() key.Key {
	return e.key
}
