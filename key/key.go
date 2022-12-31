// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package key implements algorithms and key objects for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053.
package key

import (
	"errors"

	"github.com/ldclabs/cose/iana"
)

// Key represents a COSE_Key object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#section-7
type Key IntMap

// Kty returns the key type.
// If the key is nil, it returns KtyReserved.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-type
func (k Key) Kty() int {
	if k == nil {
		return iana.KeyTypeReserved
	}

	v, _ := k.GetInt(iana.KeyParameterKty)
	return v
}

// Kid returns the key identifier.
// If the key identifier is not present, or the underlying value's Kind is not []byte, it returns nil.
func (k Key) Kid() ByteStr {
	v, _ := k.GetBytes(iana.KeyParameterKid)
	return v
}

// SetKid sets the key identifier.
func (k Key) SetKid(kid ByteStr) {
	k[iana.KeyParameterKid] = kid
}

// Alg returns the key algorithm.
// If It is elliptic-curves key and algorithm is not present,
// it will return the algorithm that matched the curve.
// Reference https://www.iana.org/assignments/cose/cose.xhtml#algorithms
func (k Key) Alg() Alg {
	v, err := k.GetInt(iana.KeyParameterAlg)
	if err == nil && v == 0 {
		// alg is optional, try lookup it by crv
		if c, err := k.GetInt(-1); err == nil {
			return Crv(c).Alg()
		}
	}
	return Alg(v)
}

// Ops returns the key operations, or nil.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
func (k Key) Ops() Ops {
	if v, ok := k[iana.KeyParameterKeyOps]; ok {
		switch x := v.(type) {
		case Ops:
			return x

		case []any:
			ops := make(Ops, len(x))
			for i, v := range x {
				op, err := ToInt(v)
				if err != nil {
					return nil
				}

				ops[i] = op
			}
			return ops
		}
	}

	return nil
}

// SetOps sets the key operations.
func (k Key) SetOps(os Ops) {
	k[iana.KeyParameterKeyOps] = os
}

// BaseIV returns the base IV to be XORed with Partial IVs.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
func (k Key) BaseIV() ByteStr {
	v, _ := k.GetBytes(iana.KeyParameterBaseIV)
	return v
}

// Has returns true if the key has the given parameter.
func (k Key) Has(p int) bool {
	return IntMap(k).Has(p)
}

// GetBool returns the value of the given parameter as a bool, or a error.
func (k Key) GetBool(p int) (bool, error) {
	return IntMap(k).GetBool(p)
}

// GetInt returns the value of the given parameter as a int, or a error.
func (k Key) GetInt(p int) (int, error) {
	return IntMap(k).GetInt(p)
}

// GetInt64 returns the value of the given parameter as a int64, or a error.
func (k Key) GetInt64(p int) (int64, error) {
	return IntMap(k).GetInt64(p)
}

// GetUint64 returns the value of the given parameter as a uint64, or a error.
func (k Key) GetUint64(p int) (uint64, error) {
	return IntMap(k).GetUint64(p)
}

// GetBytes returns the value of the given parameter as a slice of bytes, or a error.
func (k Key) GetBytes(p int) ([]byte, error) {
	return IntMap(k).GetBytes(p)
}

// GetString returns the value of the given parameter as a string, or a error.
func (k Key) GetString(p int) (string, error) {
	return IntMap(k).GetString(p)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (k Key) Bytesify() []byte {
	b, _ := k.MarshalCBOR()
	return b
}

// MarshalCBOR implements the CBOR Marshaler interface for Key.
func (k Key) MarshalCBOR() ([]byte, error) {
	return MarshalCBOR(IntMap(k))
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Key.
func (k *Key) UnmarshalCBOR(data []byte) error {
	if k == nil {
		return errors.New("cose/go/key: Key.UnmarshalCBOR: nil Key")
	}
	return UnmarshalCBOR(data, (*IntMap)(k))
}
