// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"encoding/hex"
	"encoding/json"
)

// Key represents a COSE_Key structure.
type Key IntMap

// Kty returns the key type.
// If the key is nil, it returns KtyReserved.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-type
func (k Key) Kty() Kty {
	if k == nil {
		return KtyReserved
	}

	v, _ := k.GetSmallInt(ParamKty)
	return Kty(v)
}

// Kid returns the key identifier.
// If the key identifier is not present, or the underlying value's Kind is not []byte, it returns nil.
func (k Key) Kid() ByteStr {
	v, _ := k.GetBytes(ParamKid)
	return v
}

// Alg returns the key algorithm.
// If It is elliptic-curves key and algorithm is not present,
// it will return the algorithm that matched the curve.
// Reference https://www.iana.org/assignments/cose/cose.xhtml#algorithms
func (k Key) Alg() Alg {
	v, err := k.GetSmallInt(ParamAlg)
	if err == nil && v == 0 {
		// alg is optional, try lookup it by crv
		if c, err := k.GetSmallInt(ParamCrv); err == nil {
			return Crv(c).Alg()
		}
	}
	return Alg(v)
}

// Ops returns the key operations, or nil.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
func (k Key) Ops() Ops {
	if v, ok := k[ParamOps]; ok {
		switch x := v.(type) {
		case Ops:
			return x

		case []any:
			ops := make(Ops, len(x))
			for i, v := range x {
				op, ok := v.(string)
				if !ok {
					break
				}

				ops[i] = Op(op)
			}
			return ops
		}
	}

	return nil
}

// BaseIV returns the base IV to be XORed with Partial IVs.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
func (k Key) BaseIV() ByteStr {
	v, _ := k.GetBytes(ParamBaseIV)
	return v
}

// Has returns true if the key has the given parameter.
func (k Key) Has(p IntKey) bool {
	return IntMap(k).Has(p)
}

// GetSmallInt returns the value of the given parameter as a small integer, or a error.
func (k Key) GetSmallInt(p IntKey) (int, error) {
	return IntMap(k).GetSmallInt(p)
}

// GetBytes returns the value of the given parameter as a slice of bytes, or a error.
func (k Key) GetBytes(p IntKey) ([]byte, error) {
	return IntMap(k).GetBytes(p)
}

// MarshalJSON implements the json.Marshaler interface for Key.
func (k Key) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(k))
	for n, v := range k {
		if b, ok := v.(interface{ String() string }); ok {
			m[k.ParamString(n)] = b.String()
		} else if b, ok := v.([]byte); ok {
			m[k.ParamString(n)] = hex.EncodeToString(b)
		} else {
			m[k.ParamString(n)] = v
		}
	}

	return json.Marshal(m)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (k Key) Bytesify() []byte {
	b, _ := IntMap(k).MarshalCBOR()
	return b
}

// MarshalCBOR implements the CBOR Marshaler interface for Key.
// It is the same as IntMap.MarshalCBOR.
func (k Key) MarshalCBOR() ([]byte, error) {
	return IntMap(k).MarshalCBOR()
}
