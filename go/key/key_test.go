// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title string
		json  string
		key   Key
		res   []byte
	}{
		{
			`256-Bit Symmetric COSE_Key`,
			`{"alg":"HMAC 256/64","k":"403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388","kid":"53796d6d6574726963323536","kty":"Symmetric"}`,
			map[IntKey]any{
				ParamKty: KtySymmetric,
				ParamKid: HexBytesify("53796d6d6574726963323536"),
				ParamAlg: AlgHMAC25664,
				ParamK:   HexBytesify("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
			},
			HexBytesify("a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d795693880104024c53796d6d65747269633235360304"),
		},
		{
			`ECDSA 256-Bit COSE Key`,
			`{"alg":"ES256","crv":"P-256","d":"6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19","kid":"4173796d6d65747269634543445341323536","kty":"EC2","x":"143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f","y":"60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"}`,
			map[IntKey]any{
				ParamKty: KtyEC2,
				ParamKid: HexBytesify("4173796d6d65747269634543445341323536"),
				ParamAlg: AlgES256,
				ParamCrv: CrvP256,
				ParamX:   HexBytesify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
				ParamY:   HexBytesify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
				ParamD:   HexBytesify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
			},
			HexBytesify("a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f2001010202524173796d6d657472696345434453413235360326"),
		},
	} {
		res, err := MarshalCBOR(tc.key)
		if assert.NoError(err, tc.title) {
			assert.Equal(tc.res, res, tc.title)

			data, err := json.Marshal(tc.key)
			// fmt.Println(string(data))
			if assert.NoError(err, tc.title) {
				assert.Equal(tc.json, string(data), tc.title)
			}

			var k Key
			if assert.NoError(UnmarshalCBOR(res, &k), tc.title) {
				assert.Equal(tc.res, k.Bytesify(), tc.title)
			}
		}
	}
}
