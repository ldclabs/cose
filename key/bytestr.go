// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ByteStr represents a byte string.
type ByteStr []byte

// String returns the hex string representation of the byte string.
func (bstr ByteStr) String() string {
	return hex.EncodeToString(bstr)
}

// Base64 returns the raw base64url string representation of the byte string.
func (bstr ByteStr) Base64() string {
	return base64.RawURLEncoding.EncodeToString(bstr)
}

// MarshalText implements encoding/text interface for ByteStr.
func (bstr ByteStr) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(bstr)), nil
}

// UnmarshalText implements encoding/text interface for ByteStr.
func (bstr *ByteStr) UnmarshalText(text []byte) error {
	if bstr == nil {
		return errors.New("cose/key: ByteStr: UnmarshalText on nil pointer")
	}

	data, err := hex.DecodeString(string(text))
	if err == nil {
		*bstr = append((*bstr)[0:0], data...)
	}
	return err
}

// MarshalJSON implements encoding/json interface for ByteStr.
func (bstr ByteStr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(bstr) + `"`), nil
}

// UnmarshalJSON implements encoding/json interface for ByteStr.
func (bstr *ByteStr) UnmarshalJSON(data []byte) error {
	if bstr == nil {
		return errors.New("cose/key: ByteStr: UnmarshalJSON on nil pointer")
	}
	s := string(data)
	if s == "null" {
		return nil
	}

	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("cose/key: ByteStr: UnmarshalJSON with invalid data")
	}
	data, err := hex.DecodeString(string(data[1 : len(data)-1]))
	if err == nil {
		*bstr = append((*bstr)[0:0], data...)
	}
	return err
}

// HexBytesify converts a hex string to []byte.
// It returns nil if the string is not a valid hex string.
func HexBytesify(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil
	}
	return b
}

// Base64Bytesify converts a base64url string to []byte.
// It returns nil if the string is not a valid base64url string.
func Base64Bytesify(s string) []byte {
	enc := base64.RawURLEncoding
	if strings.Contains(s, "=") {
		enc = base64.URLEncoding
	}

	b, err := enc.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// SumKid returns a 20 bytes kid with given data.
func SumKid(data []byte) ByteStr {
	sum := sha3.Sum256(data)
	id := make([]byte, 20)
	copy(id, sum[:])
	return id
}

// UnwrapBytes returns the data if err is nil, otherwise it panics.
func UnwrapBytes(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}
