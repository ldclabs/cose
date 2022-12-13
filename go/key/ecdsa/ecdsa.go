// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ecdsa

import (
	"bytes"
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new key.Key with given algorithm for ECDSA.
func GenerateKey(alg key.Alg) (key.Key, error) {
	crv, c := getCurve(alg)
	if crv == nil {
		return nil, fmt.Errorf(`cose/go/key/ecdsa: GenerateKey: algorithm mismatch %q`, alg.String())
	}

	privKey, err := goecdsa.GenerateKey(crv, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/ecdsa: GenerateKey: %w", err)
	}

	idhash := sha1.New()
	idhash.Write(privKey.PublicKey.X.Bytes())
	idhash.Write(privKey.PublicKey.Y.Bytes())

	// https://datatracker.ietf.org/doc/html/rfc9053#name-double-coordinate-curves
	return map[key.IntKey]any{
		key.ParamKty: key.KtyEC2,
		key.ParamKid: idhash.Sum(nil), // default kid, can be set to other value.
		key.ParamAlg: alg,
		key.ParamCrv: c,                 // REQUIRED
		key.ParamD:   privKey.D.Bytes(), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid ECDSA key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#section-2-1
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtyEC2 {
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid key type, expected "EC2", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamCrv, key.ParamX, key.ParamY, key.ParamD:
			// continue

		case key.ParamAlg: // optional
			switch k.Alg() {
			case key.AlgES256, key.AlgES384, key.AlgES512:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpSign, key.OpVerify:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// RECOMMENDED
	if k.Has(key.ParamKid) {
		if kid, err := k.GetBytes(key.ParamKid); err != nil || len(kid) == 0 {
			return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter kid`)
		}
	}

	_, c := getCurve(k.Alg())
	// REQUIRED
	crv, err := k.GetSmallInt(key.ParamCrv)
	if err != nil {
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter crv, %v`, err)
	}
	if crv != int(c) {
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter crv %q`, key.Crv(crv).String())
	}

	// REQUIRED for private key
	hasD := k.Has(key.ParamD)
	d, _ := k.GetBytes(key.ParamD)
	if hasD && (len(d) == 0 || len(d) > 66) {
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter d`)
	}

	// REQUIRED for public key
	// RECOMMENDED for private key
	hasX := k.Has(key.ParamX)
	x, _ := k.GetBytes(key.ParamX)

	hasY := k.Has(key.ParamY)
	y, _ := k.GetBytes(key.ParamY)
	if err != nil {
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter y, %v`, err)
	}

	if hasX || hasY {
		if len(x) == 0 || len(x) > 66 {
			return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter x`)
		}

		if len(y) == 0 || len(y) > 66 {
			return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: invalid parameter y`)
		}
	}

	ops := k.Ops()
	switch {
	case !hasD && !hasX:
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: missing parameter x or d`)

	case hasD && !ops.EmptyOrHas(key.OpSign):
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: don't include "sign"`)

	case !hasD && !ops.EmptyOrHas(key.OpVerify):
		return fmt.Errorf(`cose/go/key/ecdsa: CheckKey: don't include "verify"`)
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
			return nil, errors.New(`cose/go/key/ecdsa: ToPublicKey: missing parameter x`)
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

	crv, _ := getCurve(k.Alg())
	x, y := crv.ScalarBaseMult(d)
	pk[key.ParamX] = x.Bytes()
	pk[key.ParamY] = y.Bytes()
	return pk, nil
}

type ecdsaSigner struct {
	key     key.Key
	privKey *goecdsa.PrivateKey
}

// NewSigner creates a key.Signer for the given private key.
func NewSigner(k key.Key) (key.Signer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(key.ParamD) {
		return nil, fmt.Errorf("cose/go/key/ecdsa: NewSigner: invalid parameter d")
	}

	d, _ := k.GetBytes(key.ParamD)
	crv, _ := getCurve(k.Alg())
	privKey := new(goecdsa.PrivateKey)
	privKey.PublicKey.Curve = crv
	privKey.D = new(big.Int).SetBytes(d)
	privKey.PublicKey.X, privKey.PublicKey.Y = crv.ScalarBaseMult(d)

	x, _ := k.GetBytes(key.ParamX)
	y, _ := k.GetBytes(key.ParamY)
	if x != nil || y != nil {
		if !bytes.Equal(privKey.PublicKey.X.Bytes(), x) ||
			!bytes.Equal(privKey.PublicKey.Y.Bytes(), y) {
			return nil, fmt.Errorf("cose/go/key/ecdsa: NewSigner: invalid parameters x, y for %q", k.Kid())
		}
	}

	return &ecdsaSigner{key: k, privKey: privKey}, nil
}

// Sign implements the key.Signer interface.
// Sign computes the digital signature for data.
func (e *ecdsaSigner) Sign(data []byte) ([]byte, error) {
	hashed, err := key.ComputeHash(e.key.Alg().HashFunc(), data)
	if err != nil {
		return nil, err
	}
	r, s, err := goecdsa.Sign(rand.Reader, e.privKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/ecdsa: Sign: %w", err)
	}

	return EncodeSignature(e.privKey.Curve, r, s)
}

// Key implements the key.Signer interface.
// Key returns the private key in Signer.
func (e *ecdsaSigner) Key() key.Key {
	return e.key
}

type ecdsaVerifier struct {
	key    key.Key
	pubKey *goecdsa.PublicKey
}

// NewVerifier creates a key.Verifier for the given public key.
func NewVerifier(k key.Key) (key.Verifier, error) {
	pk, err := ToPublicKey(k)
	if err != nil {
		return nil, err
	}

	x, _ := pk.GetBytes(key.ParamX)
	y, _ := pk.GetBytes(key.ParamY)
	crv, _ := getCurve(pk.Alg())
	pubKey := &goecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !pubKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, fmt.Errorf("cose/go/key/ecdsa: NewVerifier: invalid public key")
	}

	return &ecdsaVerifier{key: pk, pubKey: pubKey}, nil
}

// Verify implements the key.Verifier interface.
// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
func (e *ecdsaVerifier) Verify(data, sig []byte) error {
	hashed, err := key.ComputeHash(e.key.Alg().HashFunc(), data)
	if err != nil {
		return fmt.Errorf("cose/go/key/ecdsa: Verify: %w", err)
	}

	r, s, err := DecodeSignature(e.pubKey.Curve, sig)
	if err != nil {
		return fmt.Errorf("cose/go/key/ecdsa: Verify: %w", err)
	}

	if !goecdsa.Verify(e.pubKey, hashed, r, s) {
		return fmt.Errorf("cose/go/key/ecdsa: Verify: invalid signature")
	}

	return nil
}

// Key implements the key.Verifier interface.
// Key returns the public key in Verifier.
func (e *ecdsaVerifier) Key() key.Key {
	return e.key
}

// EncodeSignature encodes (r, s) into a signature binary string using the
// method specified by RFC 8152 section 8.1.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
func EncodeSignature(curve elliptic.Curve, r, s *big.Int) ([]byte, error) {
	n := (curve.Params().N.BitLen() + 7) / 8
	sig := make([]byte, n*2)
	if err := i2osp(r, sig[:n]); err != nil {
		return nil, err
	}
	if err := i2osp(s, sig[n:]); err != nil {
		return nil, err
	}
	return sig, nil
}

// DecodeSignature decodes (r, s) from a signature binary string using the
// method specified by RFC 8152 section 8.1.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
func DecodeSignature(curve elliptic.Curve, sig []byte) (r, s *big.Int, err error) {
	n := (curve.Params().N.BitLen() + 7) / 8
	if len(sig) != n*2 {
		return nil, nil, fmt.Errorf("cose/go/key/ecdsa: DecodeSignature: invalid signature length: %d", len(sig))
	}

	return os2ip(sig[:n]), os2ip(sig[n:]), nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
func i2osp(x *big.Int, buf []byte) error {
	if x.Sign() < 0 {
		return errors.New("negative integer")
	}
	if x.BitLen() > len(buf)*8 {
		return errors.New("integer too large")
	}
	x.FillBytes(buf)
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
func os2ip(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}

var (
	p256 = elliptic.P256()
	p384 = elliptic.P384()
	p521 = elliptic.P521()
)

func getCurve(alg key.Alg) (elliptic.Curve, key.Crv) {
	switch alg {
	case key.AlgES256, key.AlgReserved:
		return p256, key.CrvP256

	case key.AlgES384:
		return p384, key.CrvP384

	case key.AlgES512:
		return p521, key.CrvP521

	default:
		return nil, 0
	}
}
