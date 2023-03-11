// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cose implements CBOR Object Signing and Encryption (COSE) as defined in RFC9052.
// https://datatracker.ietf.org/doc/html/rfc9052.
package cose

import "github.com/ldclabs/cose/key"

// Headers represents a COSE Generic_Headers structure.
type Headers key.IntMap

// Has returns true if the Headers has the given parameter.
func (h Headers) Has(p int) bool {
	return key.IntMap(h).Has(p)
}

// GetBool returns the value of the given parameter as a bool, or a error.
func (h Headers) GetBool(p int) (bool, error) {
	return key.IntMap(h).GetBool(p)
}

// GetInt returns the value of the given parameter as a int, or a error.
func (h Headers) GetInt(p int) (int, error) {
	return key.IntMap(h).GetInt(p)
}

// GetInt64 returns the value of the given parameter as a int64, or a error.
func (h Headers) GetInt64(p int) (int64, error) {
	return key.IntMap(h).GetInt64(p)
}

// GetUint64 returns the value of the given parameter as a uint64, or a error.
func (h Headers) GetUint64(p int) (uint64, error) {
	return key.IntMap(h).GetUint64(p)
}

// GetBytes returns the value of the given parameter as a slice of bytes, or a error.
func (h Headers) GetBytes(p int) ([]byte, error) {
	return key.IntMap(h).GetBytes(p)
}

// GetString returns the value of the given parameter as a string, or a error.
func (h Headers) GetString(p int) (string, error) {
	return key.IntMap(h).GetString(p)
}

// GetIntMap returns the value of the given parameter as a key.IntMap, or a error.
func (h Headers) GetIntMap(p int) (key.IntMap, error) {
	return key.IntMap(h).GetIntMap(p)
}

// MarshalCBOR implements the CBOR Marshaler interface for Headers.
func (h Headers) MarshalCBOR() ([]byte, error) {
	return key.IntMap(h).MarshalCBOR()
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Headers.
func (h *Headers) UnmarshalCBOR(data []byte) error {
	return (*key.IntMap)(h).UnmarshalCBOR(data)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (h Headers) Bytesify() []byte {
	return key.IntMap(h).Bytesify()
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns ([]byte{}, nil) if Headers is nil or empty.
func (h Headers) Bytes() ([]byte, error) {
	if len(h) == 0 {
		return []byte{}, nil
	}
	return h.MarshalCBOR()
}

// HeadersFromBytes decode bytes into a Headers.
// It returns (Headers{}, nil) if data is nil or empty.
func HeadersFromBytes(data []byte) (Headers, error) {
	h := Headers{}
	if len(data) > 0 {
		if err := h.UnmarshalCBOR(data); err != nil {
			return nil, err
		}
	}

	return h, nil
}
