// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesccm"
)

func TestEncrypt0Message(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title              string
		key                key.Key
		iv                 []byte
		plaintext          []byte
		toEnc              []byte
		detachedCiphertext bool
		output             []byte
	}{
		{
			`Enc-04: Encryption example for spec - Direct ECDH`,
			map[key.IntKey]any{
				key.ParamKty: key.KtySymmetric,
				key.ParamKid: []byte("our-secret2"),
				key.ParamAlg: key.AlgAESCCM1664128,
				key.ParamK:   key.Base64Bytesify("hJtXhkV8FJG-Onbc6mxCcY"),
			},
			key.HexBytesify("89F52F65A1C580933B5261A78C"),
			[]byte("This is the content."),
			key.HexBytesify("8368456E63727970743043A1010A40"),
			false,
			key.HexBytesify("D08343A1010AA1054D89F52F65A1C580933B5261A78C581C5974E1B99A3A4CC09A659AA2E9E7FFF161D38CE71CB45CE460FFB569"),
		},
	} {
		encryptor, err := tc.key.Encryptor()
		require.NoError(t, err, tc.title)

		obj := &Encrypt0Message{
			Unprotected:        Headers{HeaderLabelIV: tc.iv},
			Plaintext:          tc.plaintext,
			DetachedCiphertext: tc.detachedCiphertext,
		}

		err = obj.Encrypt(encryptor, nil)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj.toEnc, tc.title)

		// encrypt repeatedly should ok
		err = obj.Encrypt(encryptor, nil)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj.toEnc, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.output, output, tc.title)

		var obj2 Encrypt0Message
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj2), tc.title)
		require.NoError(t, obj2.Decrypt(encryptor, nil), tc.title)
		// verify repeatedly should ok
		require.NoError(t, obj2.Decrypt(encryptor, nil), tc.title)
		assert.Equal(tc.toEnc, obj2.toEnc, tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.plaintext, obj2.Plaintext, tc.title)
	}
}
