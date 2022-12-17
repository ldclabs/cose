// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesmac

import (
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterMACer(key.KtySymmetric, key.AlgAESMAC12864, New)
	key.RegisterMACer(key.KtySymmetric, key.AlgAESMAC25664, New)
	key.RegisterMACer(key.KtySymmetric, key.AlgAESMAC128128, New)
	key.RegisterMACer(key.KtySymmetric, key.AlgAESMAC256128, New)
}
