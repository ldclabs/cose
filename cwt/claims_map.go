// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"github.com/ldclabs/cose/key"
)

// ClaimsMap supports full claims for CWT.
//
// Reference https://www.iana.org/assignments/cwt/cwt.xhtml
type ClaimsMap key.IntMap

// Has returns true if the ClaimsMap has the given claim.
func (cm ClaimsMap) Has(claim int) bool {
	return key.IntMap(cm).Has(claim)
}

// GetBool returns the value of the given claim as a bool, or a error.
func (cm ClaimsMap) GetBool(claim int) (bool, error) {
	return key.IntMap(cm).GetBool(claim)
}

// GetInt returns the value of the given claim as a int, or a error.
func (cm ClaimsMap) GetInt(claim int) (int, error) {
	return key.IntMap(cm).GetInt(claim)
}

// GetInt64 returns the value of the given claim as a int64, or a error.
func (cm ClaimsMap) GetInt64(claim int) (int64, error) {
	return key.IntMap(cm).GetInt64(claim)
}

// GetUint64 returns the value of the given claim as a uint64, or a error.
func (cm ClaimsMap) GetUint64(claim int) (uint64, error) {
	return key.IntMap(cm).GetUint64(claim)
}

// GetBytes returns the value of the given claim as a slice of bytes, or a error.
func (cm ClaimsMap) GetBytes(claim int) ([]byte, error) {
	return key.IntMap(cm).GetBytes(claim)
}

// GetString returns the value of the given claim as a string, or a error.
func (cm ClaimsMap) GetString(claim int) (string, error) {
	return key.IntMap(cm).GetString(claim)
}

// GetIntMap returns the value of the given parameter as a key.IntMap, or a error.
func (cm ClaimsMap) GetIntMap(claim int) (key.IntMap, error) {
	return key.IntMap(cm).GetIntMap(claim)
}

// MarshalCBOR implements the CBOR Marshaler interface for ClaimsMap.
func (cm ClaimsMap) MarshalCBOR() ([]byte, error) {
	return key.IntMap(cm).MarshalCBOR()
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for ClaimsMap.
func (cm *ClaimsMap) UnmarshalCBOR(data []byte) error {
	return (*key.IntMap)(cm).UnmarshalCBOR(data)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (cm ClaimsMap) Bytesify() []byte {
	return key.IntMap(cm).Bytesify()
}
