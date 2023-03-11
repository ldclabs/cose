// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterSigner(iana.KeyTypeOKP, iana.AlgorithmEdDSA, iana.EllipticCurveEd25519, NewSigner)

	key.RegisterVerifier(iana.KeyTypeOKP, iana.AlgorithmEdDSA, iana.EllipticCurveEd25519, NewVerifier)
}
