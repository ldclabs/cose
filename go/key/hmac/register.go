// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	"github.com/ldclabs/cose/go/key"
)

func init() {
	key.RegisterSigner(key.KtySymmetric, key.AlgHMAC25664, key.CrvReserved, NewSigner)
	key.RegisterSigner(key.KtySymmetric, key.AlgHMAC256256, key.CrvReserved, NewSigner)
	key.RegisterSigner(key.KtySymmetric, key.AlgHMAC384384, key.CrvReserved, NewSigner)
	key.RegisterSigner(key.KtySymmetric, key.AlgHMAC512512, key.CrvReserved, NewSigner)

	key.RegisterVerifier(key.KtySymmetric, key.AlgHMAC25664, key.CrvReserved, NewVerifier)
	key.RegisterVerifier(key.KtySymmetric, key.AlgHMAC256256, key.CrvReserved, NewVerifier)
	key.RegisterVerifier(key.KtySymmetric, key.AlgHMAC384384, key.CrvReserved, NewVerifier)
	key.RegisterVerifier(key.KtySymmetric, key.AlgHMAC512512, key.CrvReserved, NewVerifier)
}
