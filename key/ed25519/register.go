// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterSigner(key.KtyOKP, key.AlgEdDSA, key.CrvEd25519, NewSigner)

	key.RegisterVerifier(key.KtyOKP, key.AlgEdDSA, key.CrvEd25519, NewVerifier)
}
