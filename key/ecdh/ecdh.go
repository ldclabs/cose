// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ecdh implements key agreement algorithm ECDH for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-direct-key-agreement.
package ecdh

import (
	goecdh "crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given curve for ECDH.
// crv is one of the iana.EllipticCurve* constants.
func GenerateKey(crv int) (key.Key, error) {
	curve := getCurve(crv)
	if curve == nil {
		return nil, fmt.Errorf(`cose/key/ecdh: GenerateKey: invalid crv %d`, crv)
	}

	kty := iana.KeyTypeEC2
	if crv == iana.EllipticCurveX25519 {
		kty = iana.KeyTypeOKP
	}
	pk, _ := curve.GenerateKey(rand.Reader) // err should never happen
	return map[any]any{
		iana.KeyParameterKty:    kty,
		iana.KeyParameterKid:    key.SumKid(pk.PublicKey().Bytes()), // default kid, can be set to other value.
		iana.EC2KeyParameterCrv: crv,                                // REQUIRED
		iana.EC2KeyParameterD:   pk.Bytes(),                         // REQUIRED
	}, nil
}

// KeyToPrivate returns a *ecdh.PrivateKey for the given Key.
func KeyToPrivate(k key.Key) (*goecdh.PrivateKey, error) {
	if !k.Has(iana.EC2KeyParameterD) {
		return nil, fmt.Errorf("cose/key/ecdh: KeyToPrivate: invalid private key")
	}

	if err := CheckKey(k); err != nil {
		return nil, err
	}

	d, _ := k.GetBytes(iana.EC2KeyParameterD)
	crv, _ := k.GetInt(iana.EC2KeyParameterCrv)
	curve := getCurve(crv)
	return curve.NewPrivateKey(d)
}

// KeyFromPrivate returns a private Key with given ecdh.PrivateKey.
func KeyFromPrivate(pk *goecdh.PrivateKey) (key.Key, error) {
	var crv int
	kty := iana.KeyTypeEC2
	switch curve := pk.Curve(); curve {
	case goecdh.P256():
		crv = iana.EllipticCurveP_256
	case goecdh.P384():
		crv = iana.EllipticCurveP_384
	case goecdh.P521():
		crv = iana.EllipticCurveP_521
	case goecdh.X25519():
		crv = iana.EllipticCurveX25519
		kty = iana.KeyTypeOKP
	default:
		return nil, fmt.Errorf("cose/key/ecdh: KeyFromPrivate: unsupported curve %q", curve)
	}

	return map[any]any{
		iana.KeyParameterKty:    kty,
		iana.KeyParameterKid:    key.SumKid(pk.PublicKey().Bytes()), // default kid, can be set to other value.
		iana.EC2KeyParameterCrv: crv,                                // REQUIRED
		iana.EC2KeyParameterD:   pk.Bytes(),                         // REQUIRED
	}, nil
}

// KeyToPublic returns a *ecdh.PublicKey for the given key.Key.
func KeyToPublic(k key.Key) (*goecdh.PublicKey, error) {
	pk, err := ToPublicKey(k)
	if err != nil {
		return nil, err
	}
	return keyToPublic(pk)
}

func keyToPublic(pk key.Key) (*goecdh.PublicKey, error) {
	crv, _ := pk.GetInt(iana.EC2KeyParameterCrv)
	x, _ := pk.GetBytes(iana.EC2KeyParameterX)
	curve := getCurve(crv)
	if curve == goecdh.X25519() {
		return curve.NewPublicKey(x)
	}

	ecdsaCurve, _ := getECDSACurve(curve)
	if ecdsaCurve == nil {
		return nil, fmt.Errorf("cose/key/ecdh: keyToPublic: invalid parameter crv %q", crv)
	}

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
		ix, iy = elliptic.UnmarshalCompressed(ecdsaCurve, compressed)
	}
	k := ecdsa.PublicKey{Curve: ecdsaCurve, X: ix, Y: iy}
	return k.ECDH()
}

// KeyFromPublic returns a public Key with given ecdh.PublicKey.
func KeyFromPublic(pk *goecdh.PublicKey) (key.Key, error) {
	data := pk.Bytes()
	curve := pk.Curve()
	if curve == goecdh.X25519() {
		return map[any]any{
			iana.KeyParameterKty:    iana.KeyTypeOKP,
			iana.KeyParameterKid:    key.SumKid(data),         // default kid, can be set to other value.
			iana.EC2KeyParameterCrv: iana.EllipticCurveX25519, // REQUIRED
			iana.EC2KeyParameterX:   data,                     // REQUIRED
		}, nil
	}

	ecdsaCurve, crv := getECDSACurve(curve)
	if ecdsaCurve == nil {
		return nil, fmt.Errorf("cose/key/ecdh: KeyFromPublic: unsupported curve %v", curve)
	}

	x, y := elliptic.Unmarshal(ecdsaCurve, data)
	return map[any]any{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    key.SumKid(data), // default kid, can be set to other value.
		iana.EC2KeyParameterCrv: crv,              // REQUIRED
		iana.EC2KeyParameterX:   x.Bytes(),        // REQUIRED
		iana.EC2KeyParameterY:   y.Bytes(),        // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid ECDH key.
func CheckKey(k key.Key) error {
	kty := k.Kty()
	if kty != iana.KeyTypeEC2 && kty != iana.KeyTypeOKP {
		return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid key type, expected "OKP":1 or "EC2":2, got %d`, kty)
	}

	hasD := k.Has(iana.EC2KeyParameterD)
	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.EC2KeyParameterCrv, iana.EC2KeyParameterX, iana.EC2KeyParameterY, iana.EC2KeyParameterD:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmECDH_SS_A256KW, iana.AlgorithmECDH_SS_A192KW, iana.AlgorithmECDH_SS_A128KW,
				iana.AlgorithmECDH_ES_A256KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A128KW,
				iana.AlgorithmECDH_SS_HKDF_512, iana.AlgorithmECDH_SS_HKDF_256, iana.AlgorithmECDH_ES_HKDF_512, iana.AlgorithmECDH_ES_HKDF_256:
			// continue
			default:
				return fmt.Errorf(`cose/key/ecdh: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationDeriveKey, iana.KeyOperationDeriveBits:
					if !hasD {
						return fmt.Errorf(`cose/key/ecdh: CheckKey: key_ops should be empty for the public key, but got %d`, op)
					}
				default:
					return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter key_ops %d`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/ecdh: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	c, err := k.GetInt(iana.EC2KeyParameterCrv)
	if err != nil {
		return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter crv, %w`, err)
	}

	curve := getCurve(c)
	if curve == nil {
		return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter crv %d`, c)
	}

	keySize := getKeySize(curve)

	// REQUIRED for private key
	d, _ := k.GetBytes(iana.EC2KeyParameterD)
	if hasD && len(d) != keySize {
		return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter d, expected %d bytes, got %d`, keySize, len(d))
	}

	// REQUIRED for public key
	// RECOMMENDED for private key
	hasX := k.Has(iana.EC2KeyParameterX)
	x, _ := k.GetBytes(iana.EC2KeyParameterX)

	hasY := k.Has(iana.EC2KeyParameterY)
	if hasX || hasY {
		if len(x) == 0 || len(x) > keySize {
			return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter x, expected %d bytes, got %d`, keySize, len(x))
		}

		if hasY {
			if kty == iana.KeyTypeOKP {
				return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter y for OKP key`)
			}

			if _, err := k.GetBool(iana.EC2KeyParameterY); err != nil { // not a bool
				y, err := k.GetBytes(iana.EC2KeyParameterY)
				if err != nil {
					return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter y, %w`, err)
				}

				if len(y) == 0 || len(y) > keySize {
					return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter y, expected %d bytes, got %d`, keySize, len(y))
				}
			}
		} else {
			if kty == iana.KeyTypeEC2 {
				return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter y for EC2 key`)
			}
		}
	}

	if !hasD && !hasX {
		return fmt.Errorf(`cose/key/ecdh: CheckKey: missing parameter d or x`)
	}

	// RECOMMENDED
	if k.Has(iana.KeyParameterKid) {
		if kid, err := k.GetBytes(iana.KeyParameterKid); err != nil || len(kid) == 0 {
			return fmt.Errorf(`cose/key/ecdh: CheckKey: invalid parameter kid`)
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

	crv, _ := k.GetInt(iana.EC2KeyParameterCrv)
	d, _ := k.GetBytes(iana.EC2KeyParameterD)
	curve := getCurve(crv)
	pk, err := curve.NewPrivateKey(d)
	if err != nil {
		return nil, err
	}

	data := pk.PublicKey().Bytes()
	nk := key.Key{
		iana.KeyParameterKty:    k[iana.KeyParameterKty],
		iana.EC2KeyParameterCrv: k[iana.EC2KeyParameterCrv],
	}

	if v, ok := k[iana.KeyParameterKid]; ok {
		nk[iana.KeyParameterKid] = v
	} else {
		nk[iana.KeyParameterKid] = key.SumKid(data)
	}

	if v, ok := k[iana.KeyParameterAlg]; ok {
		nk[iana.KeyParameterAlg] = v
	}

	if _, ok := k[iana.KeyParameterKeyOps]; ok {
		nk[iana.KeyParameterKeyOps] = key.Ops{}
	}

	if curve == goecdh.X25519() {
		nk[iana.OKPKeyParameterX] = data
		return nk, nil
	}

	ecdsaCurve, _ := getECDSACurve(curve)
	x, y := elliptic.Unmarshal(ecdsaCurve, data)
	nk[iana.EC2KeyParameterX] = x.Bytes()
	nk[iana.EC2KeyParameterY] = y.Bytes()
	return nk, nil
}

// ToCompressedKey converts the given key to a compressed Key.
// It can be used in Recipient.
func ToCompressedKey(k key.Key) (key.Key, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	if k.Kty() == iana.KeyTypeOKP {
		return k, nil
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

type ECDHer struct {
	key     key.Key
	privKey *goecdh.PrivateKey
}

// NewECDHer creates a ECDHer for the given private key.
func NewECDHer(k key.Key) (*ECDHer, error) {
	privKey, err := KeyToPrivate(k)
	if err != nil {
		return nil, err
	}
	return &ECDHer{key: k, privKey: privKey}, nil
}

// ECDH performs a ECDH exchange and returns the shared secret. The PrivateKey and PublicKey must use the same curve.
// https://pkg.go.dev/crypto/ecdh#PrivateKey.ECDH
func (e *ECDHer) ECDH(remotePublic key.Key) ([]byte, error) {
	if ops := e.key.Ops(); !ops.EmptyOrHas(iana.KeyOperationDeriveKey) &&
		!ops.EmptyOrHas(iana.KeyOperationDeriveBits) {
		return nil, fmt.Errorf("cose/key/ecdh: ECDHer.ECDH: invalid key_ops")
	}

	if remotePublic.Has(iana.EC2KeyParameterD) {
		return nil, fmt.Errorf("cose/key/ecdh: ECDHer.ECDH: remote should not be private key")
	}

	pub, err := KeyToPublic(remotePublic)
	if err != nil {
		return nil, err
	}

	return e.privKey.ECDH(pub)
}

// Key returns the private key in ECDHer.
func (e *ECDHer) Key() key.Key {
	return e.key
}

func getCurve(crv int) goecdh.Curve {
	switch crv {
	case iana.EllipticCurveP_256:
		return goecdh.P256()
	case iana.EllipticCurveP_384:
		return goecdh.P384()
	case iana.EllipticCurveP_521:
		return goecdh.P521()
	case iana.EllipticCurveX25519:
		return goecdh.X25519()
	default:
		return nil
	}
}

func getECDSACurve(curve goecdh.Curve) (elliptic.Curve, int) {
	switch curve {
	case goecdh.P256():
		return elliptic.P256(), iana.EllipticCurveP_256
	case goecdh.P384():
		return elliptic.P384(), iana.EllipticCurveP_384
	case goecdh.P521():
		return elliptic.P521(), iana.EllipticCurveP_521
	default:
		return nil, 0
	}
}

func getKeySize(curve goecdh.Curve) int {
	switch curve {
	case goecdh.P256():
		return 32
	case goecdh.P384():
		return 48
	case goecdh.P521():
		return 66
	case goecdh.X25519():
		return 32
	default:
		return 0
	}
}
