// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import "github.com/ldclabs/cose/key"

// COSE Header labels registered in the IANA "COSE Header Parameters" registry.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const (
	HeaderLabelReserved          key.IntKey = 0
	HeaderLabelAlgorithm         key.IntKey = 1 // protected header
	HeaderLabelCritical          key.IntKey = 2 // protected header
	HeaderLabelContentType       key.IntKey = 3 // unprotected header
	HeaderLabelKeyID             key.IntKey = 4 // unprotected header
	HeaderLabelIV                key.IntKey = 5 // unprotected header
	HeaderLabelPartialIV         key.IntKey = 6 // unprotected header
	HeaderLabelCounterSignature  key.IntKey = 7 // unprotected header
	HeaderLabelCounterSignature0 key.IntKey = 9 // unprotected header
)

// Headers represents a COSE Generic_Headers structure.
type Headers key.IntMap

// GetSmallInt returns the value for the key as an int in [-65536, 65536].
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value's range is out of [-65536, 65536], it returns (0, error).
func (h Headers) GetSmallInt(k key.IntKey) (int, error) {
	return key.IntMap(h).GetSmallInt(k)
}

// GetInt returns the value for the key as an int64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (h Headers) GetInt(k key.IntKey) (int64, error) {
	return key.IntMap(h).GetInt(k)
}

// GetUint returns the value for the key as an uint64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (h Headers) GetUint(k key.IntKey) (uint64, error) {
	return key.IntMap(h).GetUint(k)
}

// GetBytes returns the value for the key as an []byte.
// If the key is not present, it returns (nil, nil).
// If the underlying value is not a slice of bytes or an addressable array of bytes,
// it returns (nil, error).
func (h Headers) GetBytes(k key.IntKey) ([]byte, error) {
	return key.IntMap(h).GetBytes(k)
}

// GetString returns the value for the key as an string.
// If the key is not present, it returns ("", nil).
// If the underlying value is not a string, it returns ("", error).
func (h Headers) GetString(k key.IntKey) (string, error) {
	return key.IntMap(h).GetString(k)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (h Headers) Bytesify() []byte {
	b, _ := key.IntMap(h).MarshalCBOR()
	return b
}

// MarshalCBOR implements the CBOR Marshaler interface for Headers.
// It is the same as IntMap.MarshalCBOR.
func (h Headers) MarshalCBOR() ([]byte, error) {
	return key.IntMap(h).MarshalCBOR()
}
