// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"github.com/ldclabs/cose/key"
)

// ClaimsMap supports full claims for CWT.
//
// Reference https://www.iana.org/assignments/cwt/cwt.xhtml
type ClaimsMap key.CoseMap

// Has returns true if the ClaimsMap has the given claim.
func (cm ClaimsMap) Has(claim any) bool {
	return key.CoseMap(cm).Has(claim)
}

// Get returns the value of the given claim.
func (cm ClaimsMap) Get(claim any) any {
	return key.CoseMap(cm).Get(claim)
}

// Set sets the claim. claim key should be int or string.
func (cm ClaimsMap) Set(p, value any) error {
	return key.CoseMap(cm).Set(p, value)
}

// GetBool returns the value of the given claim as a bool, or a error.
func (cm ClaimsMap) GetBool(claim any) (bool, error) {
	return key.CoseMap(cm).GetBool(claim)
}

// GetInt returns the value of the given claim as a int, or a error.
func (cm ClaimsMap) GetInt(claim any) (int, error) {
	return key.CoseMap(cm).GetInt(claim)
}

// GetInt64 returns the value of the given claim as a int64, or a error.
func (cm ClaimsMap) GetInt64(claim any) (int64, error) {
	return key.CoseMap(cm).GetInt64(claim)
}

// GetUint64 returns the value of the given claim as a uint64, or a error.
func (cm ClaimsMap) GetUint64(claim any) (uint64, error) {
	return key.CoseMap(cm).GetUint64(claim)
}

// GetBytes returns the value of the given claim as a slice of bytes, or a error.
func (cm ClaimsMap) GetBytes(claim any) ([]byte, error) {
	return key.CoseMap(cm).GetBytes(claim)
}

// GetString returns the value of the given claim as a string, or a error.
func (cm ClaimsMap) GetString(claim any) (string, error) {
	return key.CoseMap(cm).GetString(claim)
}

// GetMap returns the value of the given parameter as a key.CoseMap, or a error.
func (cm ClaimsMap) GetMap(claim any) (key.CoseMap, error) {
	return key.CoseMap(cm).GetMap(claim)
}

// MarshalCBOR implements the CBOR Marshaler interface for ClaimsMap.
func (cm ClaimsMap) MarshalCBOR() ([]byte, error) {
	return key.CoseMap(cm).MarshalCBOR()
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for ClaimsMap.
func (cm *ClaimsMap) UnmarshalCBOR(data []byte) error {
	return (*key.CoseMap)(cm).UnmarshalCBOR(data)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (cm ClaimsMap) Bytesify() []byte {
	return key.CoseMap(cm).Bytesify()
}
