// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ecdsa implements signature algorithm ECDSA for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-ecdsa.
package ecdsa

import (
	"bytes"
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given algorithm for ECDSA.
func GenerateKey(alg int) (key.Key, error) {
	if alg == iana.AlgorithmReserved {
		alg = iana.AlgorithmES256
	}

	curve, crv := getCurve(key.Alg(alg))
	if curve == nil {
		return nil, fmt.Errorf(`cose/key/ecdsa: GenerateKey: algorithm mismatch %d`, alg)
	}

	pk, err := goecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cose/key/ecdsa: GenerateKey: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc9053#name-double-coordinate-curves
	return map[int]any{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    key.SumKid(pk.PublicKey.X.Bytes()), // default kid, can be set to other value.
		iana.KeyParameterAlg:    alg,
		iana.EC2KeyParameterCrv: crv,          // REQUIRED
		iana.EC2KeyParameterD:   pk.D.Bytes(), // REQUIRED
	}, nil
}

// KeyToPrivate returns a ecdsa.PrivateKey for the given Key.
func KeyToPrivate(k key.Key) (*goecdsa.PrivateKey, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(iana.EC2KeyParameterD) {
		return nil, fmt.Errorf("cose/key/ecdsa: KeyToPrivate: invalid private key")
	}

	d, _ := k.GetBytes(iana.EC2KeyParameterD)
	curve, _ := getCurve(k.Alg())
	privKey := new(goecdsa.PrivateKey)
	privKey.PublicKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(d)
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(d)

	if x, _ := k.GetBytes(iana.EC2KeyParameterX); x != nil && !bytes.Equal(privKey.PublicKey.X.Bytes(), x) {
		return nil, fmt.Errorf("cose/key/ecdsa: KeyToPrivate: parameter x mismatch")
	}
	if y, _ := k.GetBytes(iana.EC2KeyParameterY); y != nil && !bytes.Equal(privKey.PublicKey.Y.Bytes(), y) {
		return nil, fmt.Errorf("cose/key/ecdsa: KeyToPrivate: parameter y mismatch")
	}
	return privKey, nil
}

// KeyFromPrivate returns a private Key with given ecdsa.PrivateKey.
func KeyFromPrivate(pk *goecdsa.PrivateKey) (key.Key, error) {
	var alg, crv int
	switch curve := pk.Curve.Params().Name; curve {
	case "P-256":
		alg = iana.AlgorithmES256
		crv = iana.EllipticCurveP_256
	case "P-384":
		alg = iana.AlgorithmES384
		crv = iana.EllipticCurveP_384
	case "P-521":
		alg = iana.AlgorithmES512
		crv = iana.EllipticCurveP_521
	default:
		return nil, fmt.Errorf("cose/key/ecdsa: KeyFromPrivate: unsupported curve %q", curve)
	}

	return map[int]any{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    key.SumKid(pk.PublicKey.X.Bytes()), // default kid, can be set to other value.
		iana.KeyParameterAlg:    alg,
		iana.EC2KeyParameterCrv: crv,          // REQUIRED
		iana.EC2KeyParameterD:   pk.D.Bytes(), // REQUIRED
	}, nil
}

// KeyToPublic returns a ecdsa.PublicKey for the given key.Key.
func KeyToPublic(k key.Key) (*goecdsa.PublicKey, error) {
	pk, err := ToPublicKey(k)
	if err != nil {
		return nil, err
	}
	return keyToPublic(pk)
}

// KeyFromPublic returns a public Key with given ecdsa.PublicKey.
func KeyFromPublic(pk *goecdsa.PublicKey) (key.Key, error) {
	var alg, crv int
	switch curve := pk.Curve.Params().Name; curve {
	case "P-256":
		alg = iana.AlgorithmES256
		crv = iana.EllipticCurveP_256
	case "P-384":
		alg = iana.AlgorithmES384
		crv = iana.EllipticCurveP_384
	case "P-521":
		alg = iana.AlgorithmES512
		crv = iana.EllipticCurveP_521
	default:
		return nil, fmt.Errorf("cose/key/ecdsa: KeyFromPublic: unsupported curve %q", curve)
	}

	return map[int]any{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    key.SumKid(pk.X.Bytes()), // default kid, can be set to other value.
		iana.KeyParameterAlg:    alg,
		iana.EC2KeyParameterCrv: crv,          // REQUIRED
		iana.EC2KeyParameterX:   pk.X.Bytes(), // REQUIRED
		iana.EC2KeyParameterY:   pk.Y.Bytes(), // REQUIRED
	}, nil
}

func keyToPublic(pk key.Key) (*goecdsa.PublicKey, error) {
	curve, _ := getCurve(pk.Alg())

	x, _ := pk.GetBytes(iana.EC2KeyParameterX)
	ix := new(big.Int).SetBytes(x)

	y, _ := pk.GetBytes(iana.EC2KeyParameterY)
	iy := new(big.Int).SetBytes(y)

	if y == nil {
		boolY, err := pk.GetBool(iana.EC2KeyParameterY)
		if err != nil {
			return nil, err
		}
		compressed := make([]byte, 1+len(x))
		if boolY {
			compressed[0] = 0x03
		} else {
			compressed[0] = 0x02
		}
		copy(compressed[1:], x)
		ix, iy = elliptic.UnmarshalCompressed(curve, compressed)
	}

	if !curve.IsOnCurve(ix, iy) {
		return nil, fmt.Errorf("cose/key/ecdsa: KeyToPublic: (x, y) not on the curve")
	}

	return &goecdsa.PublicKey{
		Curve: curve,
		X:     ix,
		Y:     iy,
	}, nil
}

// CheckKey checks whether the given key is a valid ECDSA key.
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeEC2 {
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid key type, expected "EC2":2, got %d`, k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.EC2KeyParameterCrv, iana.EC2KeyParameterX, iana.EC2KeyParameterY, iana.EC2KeyParameterD:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmES256, iana.AlgorithmES384, iana.AlgorithmES512:
			// continue
			default:
				return fmt.Errorf(`cose/key/ecdsa: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationSign, iana.KeyOperationVerify:
				// continue
				default:
					return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter key_ops %d`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/ecdsa: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	c, err := k.GetInt(iana.EC2KeyParameterCrv)
	if err != nil {
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter crv, %w`, err)
	}

	curve, crv := getCurve(k.Alg())
	if curve == nil || c != crv {
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter crv %d`, c)
	}

	// REQUIRED for private key
	hasD := k.Has(iana.EC2KeyParameterD)
	d, _ := k.GetBytes(iana.EC2KeyParameterD)
	if hasD && (len(d) == 0 || len(d) > 66) {
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter d`)
	}

	// REQUIRED for public key
	// RECOMMENDED for private key
	hasX := k.Has(iana.EC2KeyParameterX)
	x, _ := k.GetBytes(iana.EC2KeyParameterX)

	hasY := k.Has(iana.EC2KeyParameterY)
	if hasX || hasY {
		if len(x) == 0 || len(x) > 66 {
			return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter x`)
		}

		if !hasY {
			return fmt.Errorf(`cose/key/ecdsa: CheckKey: missing parameter y`)
		}

		if _, err := k.GetBool(iana.EC2KeyParameterY); err != nil { // not a bool
			y, err := k.GetBytes(iana.EC2KeyParameterY)
			if err != nil {
				return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter y, %w`, err)
			}

			if len(y) == 0 || len(y) > 66 {
				return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter y`)
			}
		}
	}

	ops := k.Ops()
	switch {
	case !hasD && !hasX:
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: missing parameter d or x`)

	case hasD && !ops.EmptyOrHas(iana.KeyOperationSign):
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter key_ops, missing "sign":1`)

	case !hasD && !ops.EmptyOrHas(iana.KeyOperationVerify):
		return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter key_ops, missing "verify":2`)
	}

	// RECOMMENDED
	if k.Has(iana.KeyParameterKid) {
		if kid, err := k.GetBytes(iana.KeyParameterKid); err != nil || len(kid) == 0 {
			return fmt.Errorf(`cose/key/ecdsa: CheckKey: invalid parameter kid`)
		}
	}
	return nil
}

// ToPublicKey converts the given private key to a public key.
// If the key is already a public key, it is returned as-is.
func ToPublicKey(k key.Key) (key.Key, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if !k.Has(iana.EC2KeyParameterD) {
		return k, nil
	}

	d, _ := k.GetBytes(iana.EC2KeyParameterD)
	pk := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: k[iana.EC2KeyParameterCrv],
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

	curve, _ := getCurve(k.Alg())
	ix, iy := curve.ScalarBaseMult(d)
	x := ix.Bytes()
	y := iy.Bytes()

	if k.Has(iana.EC2KeyParameterX) {
		x2, _ := k.GetBytes(iana.EC2KeyParameterX)
		if !bytes.Equal(x, x2) {
			return nil, fmt.Errorf(`cose/key/ecdsa: ToPublicKey: parameter x mismatch`)
		}

		y2, err := k.GetBytes(iana.EC2KeyParameterY)
		if err == nil && !bytes.Equal(y, y2) {
			return nil, fmt.Errorf(`cose/key/ecdsa: ToPublicKey: parameter y mismatch`)
		}
	}

	pk[iana.EC2KeyParameterX] = x
	pk[iana.EC2KeyParameterY] = y
	return pk, nil
}

// ToCompressedKey converts the given key to a compressed Key.
// It can be used in Recipient.
func ToCompressedKey(k key.Key) (key.Key, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	ck := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: k[iana.EC2KeyParameterCrv],
	}

	if k.Has(iana.EC2KeyParameterD) {
		ck[iana.EC2KeyParameterD] = k[iana.EC2KeyParameterD]
		return ck, nil
	}

	ck[iana.EC2KeyParameterX] = k[iana.EC2KeyParameterX]

	boolY, err := k.GetBool(iana.EC2KeyParameterY)
	if err == nil {
		ck[iana.EC2KeyParameterY] = boolY
		return ck, nil
	}

	y, _ := k.GetBytes(iana.EC2KeyParameterY)
	ck[iana.EC2KeyParameterY] = new(big.Int).SetBytes(y).Bit(0) == 1 // sign bit
	return ck, nil
}

type ecdsaSigner struct {
	key     key.Key
	privKey *goecdsa.PrivateKey
}

// NewSigner creates a key.Signer for the given private key.
func NewSigner(k key.Key) (key.Signer, error) {
	privKey, err := KeyToPrivate(k)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{key: k, privKey: privKey}, nil
}

// Sign implements the key.Signer interface.
// Sign computes the digital signature for data.
func (e *ecdsaSigner) Sign(data []byte) ([]byte, error) {
	if !e.key.Ops().EmptyOrHas(iana.KeyOperationSign) {
		return nil, fmt.Errorf("cose/key/ecdsa: Signer.Sign: invalid key_ops")
	}

	hashed, err := key.ComputeHash(e.key.Alg().HashFunc(), data)
	if err != nil {
		return nil, err
	}
	r, s, err := goecdsa.Sign(rand.Reader, e.privKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("cose/key/ecdsa: Signer.Sign: %w", err)
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

	pubKey, err := keyToPublic(pk)
	if err != nil {
		return nil, err
	}
	return &ecdsaVerifier{key: pk, pubKey: pubKey}, nil
}

// Verify implements the key.Verifier interface.
// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
func (e *ecdsaVerifier) Verify(data, sig []byte) error {
	if !e.key.Ops().EmptyOrHas(iana.KeyOperationVerify) {
		return fmt.Errorf("cose/key/ecdsa: Verifier.Verify: invalid key_ops")
	}

	hashed, err := key.ComputeHash(e.key.Alg().HashFunc(), data)
	if err != nil {
		return fmt.Errorf("cose/key/ecdsa: Verifier.Verify: %w", err)
	}

	r, s, err := DecodeSignature(e.pubKey.Curve, sig)
	if err != nil {
		return fmt.Errorf("cose/key/ecdsa: Verifier.Verify: %w", err)
	}

	if !goecdsa.Verify(e.pubKey, hashed, r, s) {
		return fmt.Errorf("cose/key/ecdsa: Verifier.Verify: invalid signature")
	}

	return nil
}

// Key implements the key.Verifier interface.
// Key returns the public key in Verifier.
func (e *ecdsaVerifier) Key() key.Key {
	return e.key
}

// EncodeSignature encodes (r, s) into a signature bytes using the
// method specified by RFC 8152 section 8.1.
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

// DecodeSignature decodes (r, s) from a signature bytes using the
// method specified by RFC 8152 section 8.1.
func DecodeSignature(curve elliptic.Curve, sig []byte) (r, s *big.Int, err error) {
	n := (curve.Params().N.BitLen() + 7) / 8
	if len(sig) != n*2 {
		return nil, nil, fmt.Errorf("cose/key/ecdsa: DecodeSignature: invalid signature size, expected %d, got %d",
			n*2, len(sig))
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

func getCurve(alg key.Alg) (elliptic.Curve, int) {
	switch alg {
	case iana.AlgorithmES256:
		return p256, iana.EllipticCurveP_256
	case iana.AlgorithmES384:
		return p384, iana.EllipticCurveP_384
	case iana.AlgorithmES512:
		return p521, iana.EllipticCurveP_521
	default:
		return nil, 0
	}
}
