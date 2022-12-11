// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ecdsa

import (
	"github.com/ldclabs/cose/go/key"
)

func init() {
	key.RegisterSigner(key.KtyEC2, key.AlgES256, key.CrvP256, NewSigner)
	key.RegisterSigner(key.KtyEC2, key.AlgES384, key.CrvP384, NewSigner)
	key.RegisterSigner(key.KtyEC2, key.AlgES512, key.CrvP521, NewSigner)

	key.RegisterVerifier(key.KtyEC2, key.AlgES256, key.CrvP256, NewVerifier)
	key.RegisterVerifier(key.KtyEC2, key.AlgES384, key.CrvP384, NewVerifier)
	key.RegisterVerifier(key.KtyEC2, key.AlgES512, key.CrvP521, NewVerifier)
}
