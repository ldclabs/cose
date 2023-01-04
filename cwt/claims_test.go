// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"encoding/json"
	"testing"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"

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
		data, err := key.MarshalCBOR(tc.claims)
		require.NoError(err, tc.title)
		assert.Equal(tc.res, data, tc.title)

		jsondata, err := json.Marshal(tc.claims)
		require.NoError(err, tc.title)
		// fmt.Println(string(data))
		assert.Equal(tc.json, string(jsondata), tc.title)

		var claims2 Claims
		require.NoError(key.UnmarshalCBOR(data, &claims2), tc.title)
		assert.Equal(tc.res, claims2.Bytesify(), tc.title)

		var cm ClaimsMap
		require.NoError(key.UnmarshalCBOR(data, &cm), tc.title)
		assert.Equal(tc.res, cm.Bytesify(), tc.title)
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
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    key.HexBytesify("4173796d6d65747269634543445341323536"),
				iana.KeyParameterAlg:    iana.AlgorithmES256,
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   key.HexBytesify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
				iana.EC2KeyParameterY:   key.HexBytesify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
				iana.EC2KeyParameterD:   key.HexBytesify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
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

		s := cose.Sign1Message[Claims]{Payload: tc.claims}
		coseData, err := s.SignAndEncode(signer, nil)
		require.NoError(err, tc.title)
		assert.NotEqual(tc.output, coseData, tc.title)
		assert.NotEqual(tc.sig, s.Signature(), tc.title)
		assert.NotEqual(tc.output, s.Bytesify(), tc.title)

		s2, err := cose.VerifySign1Message[Claims](verifier, coseData, nil)
		require.NoError(err, tc.title)
		assert.Equal(tc.claims.Issuer, s2.Payload.Issuer)
		assert.Equal(tc.claims.Bytesify(), s2.Payload.Bytesify(), tc.title)
		assert.NotEqual(tc.sig, s2.Signature(), tc.title)
		assert.NotEqual(tc.output, s2.Bytesify(), tc.title)
		assert.Equal(s.Signature(), s2.Signature(), tc.title)
		assert.Equal(s.Bytesify(), s2.Bytesify(), tc.title)

		coseData2, err := s2.SignAndEncode(signer, nil)
		require.NoError(err, tc.title)
		assert.NotEqual(coseData, coseData2, tc.title)

		s3, err := cose.VerifySign1Message[Claims](verifier, tc.output, nil)
		require.NoError(err, tc.title)
		assert.Equal(tc.claims.Issuer, s3.Payload.Issuer)
		assert.Equal(tc.claims.Bytesify(), s3.Payload.Bytesify(), tc.title)
		assert.Equal(tc.sig, s3.Signature(), tc.title)
		assert.Equal(tc.output, s3.Bytesify(), tc.title)

		s4, err := cose.VerifySign1Message[ClaimsMap](verifier, tc.output, nil)
		require.NoError(err, tc.title)

		issuer, err := s4.Payload.GetString(iana.CWTClaimIss)
		require.NoError(err, tc.title)
		assert.Equal(tc.claims.Issuer, issuer)
		assert.Equal(tc.claims.Bytesify(), s4.Payload.Bytesify(), tc.title)
		assert.Equal(tc.sig, s4.Signature(), tc.title)
		assert.Equal(tc.output, s4.Bytesify(), tc.title)
	}
}
