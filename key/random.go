// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"crypto/rand"
	"encoding/binary"
)

// GetRandomBytes randomly generates n bytes.
func GetRandomBytes(n uint16) []byte {
	buf := make([]byte, n)
	rand.Read(buf) // err should never happen
	return buf
}

// GetRandomUint32 randomly generates an unsigned 32-bit integer.
func GetRandomUint32() uint32 {
	b := GetRandomBytes(4)
	return binary.BigEndian.Uint32(b)
}
