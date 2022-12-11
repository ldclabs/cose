// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ldclabs/cose/go/cose"
	"github.com/ldclabs/cose/go/key"
	_ "github.com/ldclabs/cose/go/key/ecdsa"
)

func TestCWT(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title  string
		key    key.Key
		claims Claims
		sig    []byte
		res    []byte
	}{
		{
			`Example Signed CWT`,
			map[key.IntKey]any{
				key.ParamKty: key.KtyEC2,
				key.ParamKid: key.HexByteify("4173796d6d65747269634543445341323536"),
				key.ParamAlg: key.AlgES256,
				key.ParamCrv: key.CrvP256,
				key.ParamX:   key.HexByteify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
				key.ParamY:   key.HexByteify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
				key.ParamD:   key.HexByteify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
			},
			Claims{
				Issuer:     "coap://as.example.com",
				Subject:    "erikw",
				Audience:   "coap://light.example.com",
				Expiration: 1444064944,
				NotBefore:  1443944944,
				IssuedAt:   1443944944,
				CWTID:      key.HexByteify("0b71"),
			},
			key.HexByteify("5427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"),
			key.HexByteify("d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"),
		},
	} {
		payload, err := key.MarshalCBOR(tc.claims)
		if assert.NoError(err, tc.title) {
			sm := &cose.Sign1Message{Payload: payload}

			if assert.NoError(sm.WithSign(tc.key, nil), tc.title) {
				res, err := key.MarshalCBOR(sm)
				if assert.NoError(err, tc.title) {
					assert.NotEqual(tc.sig, sm.Signature, tc.title)
					assert.NotEqual(tc.res, res, tc.title)

					var sm2 cose.Sign1Message
					if assert.NoError(key.UnmarshalCBOR(res, &sm2), tc.title) {
						if assert.NoError(sm2.Verify(tc.key, nil), tc.title) {
							assert.Equal(sm.Signature, sm2.Signature, tc.title)
							assert.Equal(res, sm2.Bytesify(), tc.title)

							var claims2 Claims
							if assert.NoError(key.UnmarshalCBOR(sm2.Payload, &claims2), tc.title) {
								assert.Equal(payload, claims2.Bytesify(), tc.title)
							}
						}
					}
				}
			}
		}
	}
}
