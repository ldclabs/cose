// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"github.com/ldclabs/cose/iana"
)

// Crv represents the key's curve.
type Crv int

// Alg returns the algorithm that matched the key's curve.
func (c Crv) Alg() Alg {
	switch c {
	case iana.EllipticCurveP_256:
		return iana.AlgorithmES256
	case iana.EllipticCurveP_384:
		return iana.AlgorithmES384
	case iana.EllipticCurveP_521:
		return iana.AlgorithmES512
	case iana.EllipticCurveEd25519:
		return iana.AlgorithmEdDSA
	case iana.EllipticCurveEd448:
		return iana.AlgorithmEdDSA
	case iana.EllipticCurveSecp256k1:
		return iana.AlgorithmES256K
	default:
		return iana.AlgorithmReserved
	}
}
