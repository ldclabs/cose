// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/aesccm"
	"github.com/ldclabs/cose/key/aesgcm"
)

func TestEncrypt0Message(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/encrypted-tests
	// https://github.com/cose-wg/Examples/tree/master/RFC8152
	for _, tc := range []struct {
		title       string
		key         key.Key
		protected   Headers
		unprotected Headers
		plaintext   []byte
		external    []byte
		toEnc       []byte
		output      []byte
		removeTag   bool
	}{
		{
			`env-pass-02: Add external data`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmA128GCM},
			Headers{iana.HeaderParameterIV: key.HexBytesify("02D1F7E6F26C43D4868D87CE")},
			[]byte("This is the content."),
			key.HexBytesify("0011bbcc22dd4455dd220099"),
			key.HexBytesify("8368456E63727970743043A101014C0011BBCC22DD4455DD220099"),
			key.HexBytesify("D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B1DC3A143880CA2883A5630DA08AE1E6E"),
			false,
		},
		{
			`enc-pass-03: Remove leading CBOR tag`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			},
			Headers{},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
				iana.HeaderParameterIV:  key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
			},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("8368456E6372797074304040"),
			key.HexBytesify("8340A20101054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B24BEE54AA5D797C8DC845929ACAA47EF"),
			true,
		},
		{
			`Enc-04: Encryption example for spec - Direct ECDH`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret2"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXhkV8FJG-Onbc6mxCcY"),
			},
			nil,
			Headers{iana.HeaderParameterIV: key.HexBytesify("89F52F65A1C580933B5261A78C")},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("8368456E63727970743043A1010A40"),
			key.HexBytesify("D08343A1010AA1054D89F52F65A1C580933B5261A78C581C5974E1B99A3A4CC09A659AA2E9E7FFF161D38CE71CB45CE460FFB569"),
			false,
		},
		{
			`Encryption example for spec - Direct key - partial IV`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret2"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXhkV8FJG-Onbc6mxCcY"),
				iana.KeyParameterBaseIV:     key.HexBytesify("89F52F65A1C58093"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmAES_CCM_16_64_128},
			Headers{iana.HeaderParameterPartialIV: key.HexBytesify("61A7")},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("8368456E63727970743043A1010A40"),
			key.HexBytesify("D08343A1010AA1064261A7581C252A8911D465C125B6764739700F0141ED09192DE139E053BD09ABCA"),
			false,
		},
	} {
		encryptor, err := tc.key.Encryptor()
		require.NoError(t, err, tc.title)

		obj := &Encrypt0Message[[]byte]{
			Protected:   tc.protected,
			Unprotected: tc.unprotected,
			Payload:     tc.plaintext,
		}

		err = obj.Encrypt(encryptor, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj.toEnc, tc.title)

		// encrypt repeatedly should ok
		err = obj.Encrypt(encryptor, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj.toEnc, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(output), tc.title)
		} else {
			assert.Equal(tc.output, output, tc.title)
		}

		var obj2 Encrypt0Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj2), tc.title)
		require.NoError(t, obj2.Decrypt(encryptor, tc.external), tc.title)
		// verify repeatedly should ok
		require.NoError(t, obj2.Decrypt(encryptor, tc.external), tc.title)
		assert.Equal(tc.toEnc, obj2.toEnc, tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.plaintext, obj2.Payload, tc.title)

		var obj3 Encrypt0Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj3), tc.title)
		require.NoError(t, obj3.Decrypt(encryptor, tc.external), tc.title)
		assert.Equal(tc.toEnc, obj3.toEnc, tc.title)
		assert.Equal(tc.plaintext, obj3.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj3.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj3.Bytesify(), tc.title)
		}

		obj4, err := DecryptEncrypt0Message[[]byte](encryptor, tc.output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj4.toEnc, tc.title)
		assert.Equal(tc.plaintext, obj4.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj4.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj4.Bytesify(), tc.title)
		}

		output, err = obj4.EncryptAndEncode(encryptor, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj4.toEnc, tc.title)

		obj4, err = DecryptEncrypt0Message[[]byte](encryptor, output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj4.toEnc, tc.title)
		assert.Equal(tc.plaintext, obj4.Payload, tc.title)
	}
}

func TestEncrypt0MessageEdgeCase(t *testing.T) {
	t.Run("common edge case", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesgcm.GenerateKey(0)
		require.NoError(t, err)

		encryptor, err := k.Encryptor()
		require.NoError(t, err)

		var obj *Encrypt0Message[[]byte]
		assert.ErrorContains(obj.UnmarshalCBOR([]byte{0x84}), "nil Encrypt0Message")

		obj = &Encrypt0Message[[]byte]{
			Payload: []byte("This is the content."),
		}
		assert.ErrorContains(obj.Decrypt(encryptor, nil), "should call Encrypt0Message.UnmarshalCBOR")

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "should call Encrypt0Message.Encrypt")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "should call Encrypt0Message.Encrypt")

		assert.Nil(obj.Bytesify())

		encryptor.Key().SetOps(iana.KeyOperationDecrypt)
		assert.ErrorContains(obj.Encrypt(encryptor, nil), "invalid key_ops")
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err, "invalid key_ops")
		encryptor.Key().SetOps(iana.KeyOperationEncrypt)
		assert.NoError(obj.Encrypt(encryptor, nil))

		encryptor.Key().SetOps(iana.KeyOperationEncrypt)
		assert.ErrorContains(obj.Decrypt(encryptor, nil), "invalid key_ops")

		encryptor.Key().SetOps(iana.KeyOperationDecrypt)
		assert.NoError(obj.Decrypt(encryptor, nil))

		data1, err := obj.MarshalCBOR()
		require.NoError(t, err)
		data2, err := key.MarshalCBOR(obj)
		require.NoError(t, err)
		assert.Equal(data1, data2)

		var obj1 Encrypt0Message[[]byte]
		assert.NoError(key.UnmarshalCBOR(data1, &obj1))
		assert.NoError(obj1.Decrypt(encryptor, nil))
		assert.Equal(obj.Payload, obj1.Payload)

		_, err = DecryptEncrypt0Message[[]byte](encryptor, data2[5:], nil)
		assert.ErrorContains(err, "cbor: ")
		obj2, err := DecryptEncrypt0Message[[]byte](encryptor, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)

		data2 = append(cwtPrefix, data2...)
		obj2, err = DecryptEncrypt0Message[[]byte](encryptor, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.NotEqual(data2, obj2.Bytesify())

		data2 = RemoveCBORTag(data2)
		obj2, err = DecryptEncrypt0Message[[]byte](encryptor, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.NotEqual(data2, obj2.Bytesify())
	})

	t.Run("iv", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesgcm.GenerateKey(iana.AlgorithmA256GCM)
		require.NoError(t, err)

		encryptor, err := k.Encryptor()
		require.NoError(t, err)

		var k2 key.Key
		assert.NoError(k2.UnmarshalCBOR(key.MustMarshalCBOR(k)))
		encryptor2, err := k2.Encryptor()
		require.NoError(t, err)

		iv := key.GetRandomBytes(uint16(encryptor.NonceSize()))
		partialIV := key.GetRandomBytes(6)

		obj := &Encrypt0Message[cbor.RawMessage]{
			Unprotected: Headers{iana.HeaderParameterIV: 123},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`IntMap.GetBytes: invalid value type`)

		obj = &Encrypt0Message[cbor.RawMessage]{
			Unprotected: Headers{iana.HeaderParameterPartialIV: 123},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`IntMap.GetBytes: invalid value type`)

		obj = &Encrypt0Message[cbor.RawMessage]{
			Unprotected: Headers{iana.HeaderParameterIV: iv[2:]},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`invalid nonce size, expected 12, got 10`)
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err,
			`invalid nonce size, expected 12, got 10`)

		obj.Unprotected[iana.HeaderParameterIV] = iv
		data, err := obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		obj1, err := DecryptEncrypt0Message[cbor.RawMessage](encryptor2, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(data, obj1.Bytesify())

		obj.Unprotected[iana.HeaderParameterPartialIV] = iv
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`both iv and partial iv are present`)
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err,
			`both iv and partial iv are present`)

		delete(obj.Unprotected, iana.HeaderParameterIV)
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`partial iv is too long`)
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err,
			`partial iv is too long`)

		obj.Unprotected[iana.HeaderParameterPartialIV] = partialIV
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`base iv is missing`)
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err,
			`base iv is missing`)

		encryptor.Key()[iana.KeyParameterBaseIV] = 123
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`IntMap.GetBytes: invalid value type`)

		encryptor.Key()[iana.KeyParameterBaseIV] = iv[:8]
		assert.NoError(obj.Encrypt(encryptor, nil))
		data, err = obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		obj1 = &Encrypt0Message[cbor.RawMessage]{}
		require.NoError(t, obj1.UnmarshalCBOR(data))
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil), "base iv is missing")

		obj1.Unprotected[iana.HeaderParameterIV] = iv
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil), "both iv and partial iv are present")

		delete(obj1.Unprotected, iana.HeaderParameterIV)
		obj1.Unprotected[iana.HeaderParameterPartialIV] = iv
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil), "partial iv is too long")

		obj1.Unprotected[iana.HeaderParameterPartialIV] = partialIV
		encryptor2.Key()[iana.KeyParameterBaseIV] = iv[:6]
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil), "message authentication failed")

		encryptor2.Key()[iana.KeyParameterBaseIV] = iv[:8]
		require.NoError(t, obj1.Decrypt(encryptor2, nil))
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(data, obj1.Bytesify())

		obj1.Unprotected[iana.HeaderParameterIV] = 123
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil),
			`IntMap.GetBytes: invalid value type`)

		delete(obj1.Unprotected, iana.HeaderParameterIV)
		obj1.Unprotected[iana.HeaderParameterPartialIV] = 123
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil),
			`IntMap.GetBytes: invalid value type`)

		obj1.Unprotected[iana.HeaderParameterPartialIV] = partialIV
		encryptor2.Key()[iana.KeyParameterBaseIV] = 123
		assert.ErrorContains(obj1.Decrypt(encryptor2, nil),
			`IntMap.GetBytes: invalid value type`)
	})

	t.Run("payload cbor.RawMessage", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesgcm.GenerateKey(iana.AlgorithmA256GCM)
		require.NoError(t, err)

		encryptor, err := k.Encryptor()
		require.NoError(t, err)

		obj := &Encrypt0Message[cbor.RawMessage]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmA192GCM},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`encryptor'alg mismatch, expected 2, got 3`)
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err,
			`encryptor'alg mismatch, expected 2, got 3`)

		obj.Protected[iana.HeaderParameterAlg] = iana.AlgorithmA256GCM
		data, err := obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		k1, err := aesgcm.GenerateKey(iana.AlgorithmA192GCM)
		require.NoError(t, err)
		encryptor1, err := k1.Encryptor()
		require.NoError(t, err)
		_, err = DecryptEncrypt0Message[cbor.RawMessage](encryptor1, data, nil)
		assert.ErrorContains(err,
			`encryptor'alg mismatch, expected 3, got 2`)

		obj1, err := DecryptEncrypt0Message[cbor.RawMessage](encryptor, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(data, obj1.Bytesify())
	})

	t.Run("payload T", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesccm.GenerateKey(iana.AlgorithmAES_CCM_64_64_256)
		require.NoError(t, err)

		encryptor, err := k.Encryptor()
		require.NoError(t, err)

		type T struct {
			Str string
		}

		obj := &Encrypt0Message[T]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmAES_CCM_64_64_256},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     T{"This is the content."},
		}

		data, err := obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		obj1, err := DecryptEncrypt0Message[T](encryptor, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload.Str, obj1.Payload.Str)
		assert.Equal(data, obj1.Bytesify())

		_, err = DecryptEncrypt0Message[Headers](encryptor, data, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae := make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[4])
		datae[4] = 0x60
		_, err = DecryptEncrypt0Message[T](encryptor, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[7])
		datae[7] = 0x60
		_, err = DecryptEncrypt0Message[T](encryptor, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		obj = &Encrypt0Message[T]{
			Protected: Headers{
				iana.HeaderParameterAlg:      iana.AlgorithmAES_CCM_64_64_256,
				iana.HeaderParameterReserved: func() {},
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: T{"This is the content."},
		}

		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err, "unsupported type: func()")

		obje := &Encrypt0Message[func()]{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmAES_CCM_64_64_256,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: func() {},
		}

		_, err = obje.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err, "unsupported type: func()")
	})
}
