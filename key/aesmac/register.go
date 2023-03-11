// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesmac

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmAES_MAC_128_64, New)
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmAES_MAC_256_64, New)
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmAES_MAC_128_128, New)
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmAES_MAC_256_128, New)
}
