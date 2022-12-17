// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesmac"
)

func TestMac0(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title   string
		key     key.Key
		toMac   []byte
		payload []byte
		output  []byte
	}{
		{
			`MAC0 example with direct shared key and AES-MAC/64`,
			map[key.IntKey]any{
				key.ParamKty: key.KtySymmetric,
				key.ParamKid: []byte("our-secret"),
				key.ParamAlg: key.AlgAESMAC25664,
				key.ParamK:   key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			key.HexBytesify("84644D41433043A1010F4054546869732069732074686520636F6E74656E742E"),
			[]byte("This is the content."),
			key.HexBytesify("D18443A1010FA054546869732069732074686520636F6E74656E742E48726043745027214F"),
		},
	} {
		macer, err := tc.key.MACer()
		require.NoError(t, err, tc.title)

		obj := &Mac0Message[[]byte]{Unprotected: Headers{}, Payload: tc.payload}
		err = obj.Compute(macer, nil)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj.toMac, tc.title)

		// compute repeatedly should ok
		err = obj.Compute(macer, nil)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj.toMac, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.output, output, tc.title)

		var obj2 Mac0Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(output, &obj2), tc.title)
		require.NoError(t, obj2.Verify(macer, nil), tc.title)
		// verify repeatedly should ok
		require.NoError(t, obj2.Verify(macer, nil), tc.title)
		assert.Equal(tc.toMac, obj2.toMac, tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.payload, obj2.Payload, tc.title)
	}
}
