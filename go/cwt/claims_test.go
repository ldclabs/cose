// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"encoding/json"
	"testing"

	"github.com/ldclabs/cose/go/cose"
	"github.com/ldclabs/cose/go/key"
	_ "github.com/ldclabs/cose/go/key/ecdsa"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	for _, tc := range []struct {
		title  string
		json   string
		claims Claims
		res    []byte
	}{
		{
			`Example CWT Claims Set`,
			`{"iss":"coap://as.example.com","sub":"erikw","aud":"coap://light.example.com","exp":1444064944,"nbf":1443944944,"iat":1443944944,"cti":"0b71"}`,
			Claims{
				Issuer:     "coap://as.example.com",
				Subject:    "erikw",
				Audience:   "coap://light.example.com",
				Expiration: 1444064944,
				NotBefore:  1443944944,
				IssuedAt:   1443944944,
				CWTID:      key.HexBytesify("0b71"),
			},
			key.HexBytesify("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"),
		},
	} {
		res, err := key.MarshalCBOR(tc.claims)
		require.NoError(err, tc.title)
		assert.Equal(tc.res, res, tc.title)

		data, err := json.Marshal(tc.claims)
		require.NoError(err, tc.title)
		// fmt.Println(string(data))
		assert.Equal(tc.json, string(data), tc.title)

		var claims2 Claims
		require.NoError(key.UnmarshalCBOR(res, &claims2), tc.title)
		assert.Equal(tc.res, claims2.Bytesify(), tc.title)
	}
}

func TestClaimsSign1AndVerify(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	for _, tc := range []struct {
		title  string
		key    key.Key
		claims Claims
		sig    []byte
		output []byte
	}{
		{
			`Case: Example Signed CWT`,
			map[key.IntKey]any{
				key.ParamKty: key.KtyEC2,
				key.ParamKid: key.HexBytesify("4173796d6d65747269634543445341323536"),
				key.ParamAlg: key.AlgES256,
				key.ParamCrv: key.CrvP256,
				key.ParamX:   key.HexBytesify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
				key.ParamY:   key.HexBytesify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
				key.ParamD:   key.HexBytesify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
			},
			Claims{
				Issuer:     "coap://as.example.com",
				Subject:    "erikw",
				Audience:   "coap://light.example.com",
				Expiration: 1444064944,
				NotBefore:  1443944944,
				IssuedAt:   1443944944,
				CWTID:      key.HexBytesify("0b71"),
			},
			key.HexBytesify("5427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"),
			key.HexBytesify("d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"),
		},
	} {
		signer, err := tc.key.Signer()
		require.NoError(err, tc.title)

		verifier, err := tc.key.Verifier()
		require.NoError(err, tc.title)

		coseData, err := tc.claims.Sign1AndEncode(signer, nil)
		require.NoError(err, tc.title)
		assert.NotEqual(tc.output, coseData, tc.title)

		claims2, err := Verify1AndDecode(verifier, coseData, nil)
		require.NoError(err, tc.title)
		assert.Equal(tc.claims.Bytesify(), claims2.Bytesify(), tc.title)

		coseData2, err := claims2.Sign1AndEncode(signer, nil)
		require.NoError(err, tc.title)
		assert.NotEqual(coseData, coseData2, tc.title)

		claims3, err := Verify1AndDecode(verifier, tc.output, nil)
		require.NoError(err, tc.title)
		assert.Equal(tc.claims.Bytesify(), claims3.Bytesify(), tc.title)

		s, err := cose.VerifySign1Message(verifier, tc.output, nil)
		require.NoError(err, tc.title)
		assert.Equal(tc.sig, s.Signature(), tc.title)
		assert.Equal(tc.output, s.Bytesify(), tc.title)
	}
}
