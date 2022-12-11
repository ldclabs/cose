// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"encoding/hex"
)

type ByteStr []byte

func (bstr ByteStr) String() string {
	return hex.EncodeToString(bstr)
}

func (bstr ByteStr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(bstr) + `"`), nil
}

// HexByteify converts a hex string to []byte.
func HexByteify(h string) []byte {
	b, _ := hex.DecodeString(h)
	return b
}
