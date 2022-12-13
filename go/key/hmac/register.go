// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	"github.com/ldclabs/cose/go/key"
)

func init() {
	key.RegisterMACer(key.KtySymmetric, key.AlgHMAC25664, NewHMAC)
	key.RegisterMACer(key.KtySymmetric, key.AlgHMAC256256, NewHMAC)
	key.RegisterMACer(key.KtySymmetric, key.AlgHMAC384384, NewHMAC)
	key.RegisterMACer(key.KtySymmetric, key.AlgHMAC512512, NewHMAC)
}
