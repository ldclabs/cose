// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"bytes"
	goed25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/ldclabs/cose/go/key"
)

func GenerateKey() (key.Key, error) {
	_, privKey, err := goed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cose/key/ed25519: GenerateKey: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
	// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
	return map[key.IntKey]any{
		key.ParamKty: key.KtyOKP,
		key.ParamAlg: key.AlgEdDSA,
		key.ParamCrv: key.CrvEd25519, // REQUIRED
		key.ParamD:   privKey.Seed(), // REQUIRED
	}, nil
}

// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
// https://datatracker.ietf.org/doc/html/rfc9053#name-octet-key-pair
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtyOKP {
		return fmt.Errorf(`cose/key/ed25519: CheckKey: invalid key type, expected "OKP", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamCrv, key.ParamX, key.ParamD:
			// continue

		case key.ParamAlg: // optional
			if k.Alg() != key.AlgEdDSA {
				return fmt.Errorf(`cose/key/ed25519: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpSign, key.OpVerify:
				// continue
				default:
					return fmt.Errorf(`cose/key/ed25519: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/ed25519: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// RECOMMENDED
	if x, ok := k.GetBstr(key.ParamKid); ok && len(x) == 0 {
		return fmt.Errorf(`cose/key/ed25519: CheckKey: invalid parameter kid`)
	}

	// REQUIRED
	if cc, ok := k.GetInt(key.ParamCrv); !ok || cc != int(key.CrvEd25519) {
		return fmt.Errorf(`cose/key/ed25519: CheckKey: invalid parameter crv %q`, key.Crv(cc).String())
	}

	// REQUIRED for private key
	d, okd := k.GetBstr(key.ParamD)
	if okd && len(d) != goed25519.SeedSize {
		return fmt.Errorf(`cose/key/ed25519: CheckKey: invalid parameter d`)
	}

	// REQUIRED for public key
	// RECOMMENDED for private key
	x, okx := k.GetBstr(key.ParamX)
	if okx && len(x) != goed25519.PublicKeySize {
		return fmt.Errorf(`cose/key/ed25519: CheckKey: invalid parameter x`)
	}

	ops := k.Ops()
	switch {
	case !okx && !okd:
		return fmt.Errorf(`cose/key/ed25519: CheckKey: missing parameter x or d`)

	case okd && !ops.EmptyOrHas(key.OpSign):
		return fmt.Errorf(`cose/key/ed25519: CheckKey: don't include "sign"`)

	case !okd && !ops.EmptyOrHas(key.OpVerify):
		return fmt.Errorf(`cose/key/ed25519: CheckKey: don't include "verify"`)
	}

	return nil
}

func ToPublicKey(k key.Key) (key.Key, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	d, ok := k.GetBstr(key.ParamD)
	if !ok {
		return k, nil
	}

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

func NewSigner(k key.Key) (key.Signer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	d, ok := k.GetBstr(key.ParamD)
	if !ok {
		return nil, fmt.Errorf("cose/key/ed25519: NewSigner: invalid key")
	}

	privKey := goed25519.NewKeyFromSeed(d)

	x, okx := k.GetBstr(key.ParamX)
	if okx {
		if !bytes.Equal(privKey.Public().([]byte), x) {
			return nil, fmt.Errorf("cose/key/ed25519: NewSigner: invalid parameters x, y")
		}
	}

	return &ed25519Signer{key: k, privKey: privKey}, nil
}

// Sign computes a signature for the given data.
func (e *ed25519Signer) Sign(data []byte) ([]byte, error) {
	return goed25519.Sign(e.privKey, data), nil
}

type ed25519Verifier struct {
	key    key.Key
	pubKey goed25519.PublicKey
}

func NewVerifier(k key.Key) (key.Verifier, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	x, ok := k.GetBstr(key.ParamX)
	if !ok {
		return nil, fmt.Errorf("cose/key/ed25519: NewVerifier: invalid key")
	}

	return &ed25519Verifier{key: k, pubKey: goed25519.PublicKey(x)}, nil
}

func (e *ed25519Verifier) Verify(data, sig []byte) error {
	if !goed25519.Verify(e.pubKey, data, sig) {
		return fmt.Errorf("cose/key/ed25519: Verify: invalid signature")
	}

	return nil
}
