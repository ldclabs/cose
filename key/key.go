// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package key implements algorithms and key objects for COSE as defined in RFC9052 and RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects.
// https://datatracker.ietf.org/doc/html/rfc9053.
package key

import (
	"github.com/ldclabs/cose/iana"
)

// Key represents a COSE_Key object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects.
type Key CoseMap

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
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#algorithms
func (k Key) Alg() Alg {
	v, err := k.GetInt(iana.KeyParameterAlg)
	if err == nil && v == 0 {
		// alg is optional, try lookup it by crv ( or iana.EC2KeyParameterCrv)
		if c, err := k.GetInt(iana.OKPKeyParameterCrv); err == nil {
			return CrvAlg(c)
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

		case []int:
			ops := make(Ops, len(x))
			copy(ops, x)
			return ops

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
// If operations is empty, it will remove the key_ops field.
func (k Key) SetOps(os ...int) {
	if len(os) > 0 {
		k[iana.KeyParameterKeyOps] = os
	} else {
		delete(k, iana.KeyParameterKeyOps)
	}
}

// BaseIV returns the base IV to be XORed with Partial IVs.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
func (k Key) BaseIV() ByteStr {
	v, _ := k.GetBytes(iana.KeyParameterBaseIV)
	return v
}

// Has returns true if the key has the given parameter.
func (k Key) Has(p any) bool {
	return CoseMap(k).Has(p)
}

// Get returns the value of the given parameter.
func (k Key) Get(p any) any {
	return CoseMap(k).Get(p)
}

// Set sets the parameter. parameter key should be int or string.
func (k Key) Set(p, value any) error {
	return CoseMap(k).Set(p, value)
}

// GetBool returns the value of the given parameter as a bool, or a error.
func (k Key) GetBool(p any) (bool, error) {
	return CoseMap(k).GetBool(p)
}

// GetInt returns the value of the given parameter as a int, or a error.
func (k Key) GetInt(p any) (int, error) {
	return CoseMap(k).GetInt(p)
}

// GetInt64 returns the value of the given parameter as a int64, or a error.
func (k Key) GetInt64(p any) (int64, error) {
	return CoseMap(k).GetInt64(p)
}

// GetUint64 returns the value of the given parameter as a uint64, or a error.
func (k Key) GetUint64(p any) (uint64, error) {
	return CoseMap(k).GetUint64(p)
}

// GetBytes returns the value of the given parameter as a slice of bytes, or a error.
func (k Key) GetBytes(p any) ([]byte, error) {
	return CoseMap(k).GetBytes(p)
}

// GetString returns the value of the given parameter as a string, or a error.
func (k Key) GetString(p any) (string, error) {
	return CoseMap(k).GetString(p)
}

// MarshalCBOR implements the CBOR Marshaler interface for Key.
func (k Key) MarshalCBOR() ([]byte, error) {
	return CoseMap(k).MarshalCBOR()
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Key.
func (k *Key) UnmarshalCBOR(data []byte) error {
	return (*CoseMap)(k).UnmarshalCBOR(data)
}

// MarshalText implements encoding/text interface for Key.
func (k Key) MarshalText() ([]byte, error) {
	return CoseMap(k).MarshalText()
}

// UnmarshalText implements encoding/text interface for Key.
func (k *Key) UnmarshalText(text []byte) error {
	return (*CoseMap)(k).UnmarshalText(text)
}

// MarshalJSON implements encoding/json interface for Key.
func (k Key) MarshalJSON() ([]byte, error) {
	return CoseMap(k).MarshalJSON()
}

// UnmarshalJSON implements encoding/json interface for Key.
func (k *Key) UnmarshalJSON(text []byte) error {
	return (*CoseMap)(k).UnmarshalJSON(text)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (k Key) Bytesify() []byte {
	return CoseMap(k).Bytesify()
}
