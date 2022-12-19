// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ecdsa

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterSigner(iana.KeyTypeEC2, iana.AlgorithmES256, iana.EllipticCurveP_256, NewSigner)
	key.RegisterSigner(iana.KeyTypeEC2, iana.AlgorithmES384, iana.EllipticCurveP_384, NewSigner)
	key.RegisterSigner(iana.KeyTypeEC2, iana.AlgorithmES512, iana.EllipticCurveP_521, NewSigner)

	key.RegisterVerifier(iana.KeyTypeEC2, iana.AlgorithmES256, iana.EllipticCurveP_256, NewVerifier)
	key.RegisterVerifier(iana.KeyTypeEC2, iana.AlgorithmES384, iana.EllipticCurveP_384, NewVerifier)
	key.RegisterVerifier(iana.KeyTypeEC2, iana.AlgorithmES512, iana.EllipticCurveP_521, NewVerifier)
}
