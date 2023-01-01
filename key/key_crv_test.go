// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/stretchr/testify/assert"
)

func TestCrvAlg(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		input  int
		output Alg
	}{
		{iana.EllipticCurveP_256, iana.AlgorithmES256},
		{iana.EllipticCurveP_384, iana.AlgorithmES384},
		{iana.EllipticCurveP_521, iana.AlgorithmES512},
		{iana.EllipticCurveEd25519, iana.AlgorithmEdDSA},
		{iana.EllipticCurveEd448, iana.AlgorithmEdDSA},
		{iana.EllipticCurveSecp256k1, iana.AlgorithmES256K},
		{0, iana.AlgorithmReserved},
		{9, iana.AlgorithmReserved},
		{-1, iana.AlgorithmReserved},
	} {
		assert.Equal(tc.output, CrvAlg(tc.input))
	}
}
