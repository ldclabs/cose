// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"github.com/ldclabs/cose/key"
)

const (
	KeyIss key.IntKey = 1
	KeySub key.IntKey = 2
	KeyAud key.IntKey = 3
	KeyExp key.IntKey = 4
	KeyNbf key.IntKey = 5
	KeyIat key.IntKey = 6
	KeyCti key.IntKey = 7
)

// ClaimsMap is a set of rich claims for CWT.
//
// Reference https://www.iana.org/assignments/cwt/cwt.xhtml
type ClaimsMap key.IntMap

// Has returns true if the ClaimsMap contains the key.
func (cm ClaimsMap) Has(k key.IntKey) bool {
	return key.IntMap(cm).Has(k)
}

// GetSmallInt returns the value for the key as an int in [-65536, 65536].
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value's range is out of [-65536, 65536], it returns (0, error).
func (cm ClaimsMap) GetSmallInt(k key.IntKey) (int, error) {
	return key.IntMap(cm).GetSmallInt(k)
}

// GetInt returns the value for the key as an int64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (cm ClaimsMap) GetInt(k key.IntKey) (int64, error) {
	return key.IntMap(cm).GetInt(k)
}

// GetUint returns the value for the key as an uint64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (cm ClaimsMap) GetUint(k key.IntKey) (uint64, error) {
	return key.IntMap(cm).GetUint(k)
}

// GetBytes returns the value for the key as an []byte.
// If the key is not present, it returns (nil, nil).
// If the underlying value is not a slice of bytes or an addressable array of bytes,
// it returns (nil, error).
func (cm ClaimsMap) GetBytes(k key.IntKey) ([]byte, error) {
	return key.IntMap(cm).GetBytes(k)
}

// GetString returns the value for the key as an string.
// If the key is not present, it returns ("", nil).
// If the underlying value is not a string, it returns ("", error).
func (cm ClaimsMap) GetString(k key.IntKey) (string, error) {
	return key.IntMap(cm).GetString(k)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (c ClaimsMap) Bytesify() []byte {
	b, _ := key.IntMap(c).MarshalCBOR()
	return b
}

// MarshalCBOR implements the CBOR Marshaler interface for ClaimsMap.
// It is the same as IntMap.MarshalCBOR.
func (c ClaimsMap) MarshalCBOR() ([]byte, error) {
	return key.IntMap(c).MarshalCBOR()
}
