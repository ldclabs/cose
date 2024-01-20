// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cose implements CBOR Object Signing and Encryption (COSE) as defined in RFC9052.
// https://datatracker.ietf.org/doc/html/rfc9052.
package cose

import "github.com/ldclabs/cose/key"

// Headers represents a COSE Generic_Headers structure.
type Headers key.CoseMap

// Has returns true if the Headers has the given parameter.
func (h Headers) Has(p any) bool {
	return key.CoseMap(h).Has(p)
}

// Get returns the value of the given parameter.
func (h Headers) Get(p any) any {
	return key.CoseMap(h).Get(p)
}

// Set sets the parameter. parameter key should be int or string.
func (h Headers) Set(p, value any) error {
	return key.CoseMap(h).Set(p, value)
}

// GetBool returns the value of the given parameter as a bool, or a error.
func (h Headers) GetBool(p any) (bool, error) {
	return key.CoseMap(h).GetBool(p)
}

// GetInt returns the value of the given parameter as a int, or a error.
func (h Headers) GetInt(p any) (int, error) {
	return key.CoseMap(h).GetInt(p)
}

// GetInt64 returns the value of the given parameter as a int64, or a error.
func (h Headers) GetInt64(p any) (int64, error) {
	return key.CoseMap(h).GetInt64(p)
}

// GetUint64 returns the value of the given parameter as a uint64, or a error.
func (h Headers) GetUint64(p any) (uint64, error) {
	return key.CoseMap(h).GetUint64(p)
}

// GetBytes returns the value of the given parameter as a slice of bytes, or a error.
func (h Headers) GetBytes(p any) ([]byte, error) {
	return key.CoseMap(h).GetBytes(p)
}

// GetString returns the value of the given parameter as a string, or a error.
func (h Headers) GetString(p any) (string, error) {
	return key.CoseMap(h).GetString(p)
}

// GetMap returns the value of the given parameter as a key.CoseMap, or a error.
func (h Headers) GetMap(p any) (key.CoseMap, error) {
	return key.CoseMap(h).GetMap(p)
}

// MarshalCBOR implements the CBOR Marshaler interface for Headers.
func (h Headers) MarshalCBOR() ([]byte, error) {
	return key.CoseMap(h).MarshalCBOR()
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Headers.
func (h *Headers) UnmarshalCBOR(data []byte) error {
	return (*key.CoseMap)(h).UnmarshalCBOR(data)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (h Headers) Bytesify() []byte {
	return key.CoseMap(h).Bytesify()
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
