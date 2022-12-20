// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ldclabs/cose/iana"
)

func TestKey(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title string
		key   Key
		res   []byte
	}{
		{
			`256-Bit Symmetric COSE_Key`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        HexBytesify("53796d6d6574726963323536"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
				iana.SymmetricKeyParameterK: HexBytesify("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
			},
			HexBytesify("a40104024c53796d6d65747269633235360304205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
		},
		{
			`ECDSA 256-Bit COSE Key`,
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    HexBytesify("4173796d6d65747269634543445341323536"),
				iana.KeyParameterAlg:    iana.AlgorithmES256,
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   HexBytesify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
				iana.EC2KeyParameterY:   HexBytesify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
				iana.EC2KeyParameterD:   HexBytesify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
			},
			HexBytesify("a7010202524173796d6d6574726963454344534132353603262001215820143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f22582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b92358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
		},
	} {
		res, err := MarshalCBOR(tc.key)
		if assert.NoError(err, tc.title) {
			assert.Equal(tc.res, res, tc.title)

			var k Key
			if assert.NoError(UnmarshalCBOR(res, &k), tc.title) {
				assert.Equal(tc.res, k.Bytesify(), tc.title)
			}
		}
	}
}