// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmHMAC_256_64, New)
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmHMAC_256_256, New)
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmHMAC_384_384, New)
	key.RegisterMACer(iana.KeyTypeSymmetric, iana.AlgorithmHMAC_512_512, New)
}
