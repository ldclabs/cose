// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"github.com/fxamacker/cbor/v2"
)

var encOpts = cbor.EncOptions{
	Sort:        cbor.SortBytewiseLexical,
	IndefLength: cbor.IndefLengthForbidden,
}
var encMode, _ = encOpts.EncMode()

var decOpts = cbor.DecOptions{
	DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	IndefLength: cbor.IndefLengthForbidden,
}
var decMode, _ = decOpts.DecMode()

// MarshalCBOR marshals value with the special cbor.EncOptions.
func MarshalCBOR(v any) ([]byte, error) {
	data, err := encMode.Marshal(v)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// MustMarshalCBOR marshals value with the special cbor.EncOptions.
// It will panic if marshaling failed.
func MustMarshalCBOR(v any) []byte {
	data, err := encMode.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// UnmarshalCBOR unmarshals data into value with the special cbor.DecOptions.
func UnmarshalCBOR(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
}

// ValidCBOR returns true if data is valid CBOR.
func ValidCBOR(data []byte) error {
	return decMode.Valid(data)
}
