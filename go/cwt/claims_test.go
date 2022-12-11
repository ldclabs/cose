// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"encoding/json"
	"testing"

	"github.com/ldclabs/cose/go/key"
	"github.com/stretchr/testify/assert"
)

func TestClaims(t *testing.T) {
	assert := assert.New(t)

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
				CWTID:      key.HexByteify("0b71"),
			},
			key.HexByteify("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"),
		},
	} {
		res, err := key.MarshalCBOR(tc.claims)
		if assert.NoError(err, tc.title) {
			assert.Equal(tc.res, res, tc.title)

			data, err := json.Marshal(tc.claims)
			// fmt.Println(string(data))
			if assert.NoError(err, tc.title) {
				assert.Equal(tc.json, string(data), tc.title)
			}

			var claims2 Claims
			if assert.NoError(key.UnmarshalCBOR(res, &claims2), tc.title) {
				assert.Equal(tc.res, claims2.Bytesify(), tc.title)
			}
		}
	}
}
