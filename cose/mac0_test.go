// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/aesmac"
	"github.com/ldclabs/cose/key/hmac"
)

func TestMac0(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/mac0-tests
	for _, tc := range []struct {
		title       string
		key         key.Key
		protected   Headers
		unprotected Headers
		payload     []byte
		external    []byte
		toMac       []byte
		output      []byte
		removeTag   bool
	}{
		{
			`mac-pass-02: External Data`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			[]byte("This is the content."),
			key.HexBytesify("ff00ee11dd22cc33bb44aa559966"),
			key.HexBytesify("84644D414330404EFF00EE11DD22CC33BB44AA55996654546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D18440A1010554546869732069732074686520636F6E74656E742E58200FECAEC59BB46CC8A488AACA4B205E322DD52696B75A45768D3C302DD4BAE2F7"),
			false,
		},
		{
			`mac-pass-03: Remvove cbor tag`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("84644D414330404054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("8440A1010554546869732069732074686520636F6E74656E742E5820176DCE14C1E57430C13658233F41DC89AA4FA0FF9B8783F23B0EF51CA6B026BC"),
			true,
		},
		{
			`HMAC-01: Direct key + HMAC-SHA256`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			Headers{},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("84644D41433043A101054054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58"),
			false,
		},
		{
			`MAC0 example with direct shared key and AES-MAC/64`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_256_64,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmAES_MAC_256_64},
			Headers{},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("84644D41433043A1010F4054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D18443A1010FA054546869732069732074686520636F6E74656E742E48726043745027214F"),
			false,
		},
	} {
		macer, err := tc.key.MACer()
		require.NoError(t, err, tc.title)

		obj := &Mac0Message[[]byte]{
			Protected:   tc.protected,
			Unprotected: tc.unprotected,
			Payload:     tc.payload,
		}
		err = obj.Compute(macer, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj.toMac, tc.title)

		// compute repeatedly should ok
		err = obj.Compute(macer, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj.toMac, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(output), tc.title)
		} else {
			assert.Equal(tc.output, output, tc.title)
		}

		var obj2 Mac0Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(output, &obj2), tc.title)
		require.NoError(t, obj2.Verify(macer, tc.external), tc.title)
		// verify repeatedly should ok
		require.NoError(t, obj2.Verify(macer, tc.external), tc.title)
		assert.Equal(tc.toMac, obj2.toMac, tc.title)
		assert.Equal(obj.Tag(), obj2.Tag(), tc.title)
		assert.Equal(tc.payload, obj2.Payload, tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)

		var obj3 Mac0Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj3), tc.title)
		require.NoError(t, obj3.Verify(macer, tc.external), tc.title)
		assert.Equal(tc.toMac, obj3.toMac, tc.title)
		assert.Equal(obj.Tag(), obj3.Tag(), tc.title)
		assert.Equal(tc.payload, obj3.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj3.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj3.Bytesify(), tc.title)
		}

		obj4, err := VerifyMac0Message[[]byte](macer, tc.output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj4.toMac, tc.title)
		assert.Equal(obj.Tag(), obj4.Tag(), tc.title)
		assert.Equal(tc.payload, obj4.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj4.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj4.Bytesify(), tc.title)
		}

		output, err = obj4.ComputeAndEncode(macer, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj4.toMac, tc.title)
		assert.Equal(obj.Tag(), obj4.Tag(), tc.title)

		obj4, err = VerifyMac0Message[[]byte](macer, output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj4.toMac, tc.title)
		assert.Equal(obj.Tag(), obj4.Tag(), tc.title)
		assert.Equal(tc.payload, obj4.Payload, tc.title)
	}
}

func TestMac0EdgeCase(t *testing.T) {
	t.Run("common edge case", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesmac.GenerateKey(0)
		require.NoError(t, err)

		macer, err := k.MACer()
		require.NoError(t, err)

		var obj *Mac0Message[[]byte]
		assert.ErrorContains(obj.UnmarshalCBOR([]byte{0x84}), "nil Mac0Message")

		obj = &Mac0Message[[]byte]{
			Payload: []byte("This is the content."),
		}
		assert.ErrorContains(obj.Verify(macer, nil), "should call Mac0Message.UnmarshalCBOR")

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "should call Mac0Message.Compute")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "should call Mac0Message.Compute")

		assert.Nil(obj.Bytesify())
		assert.Nil(obj.Tag())

		macer.Key().SetOps(iana.KeyOperationMacVerify)
		assert.ErrorContains(obj.Compute(macer, nil), "invalid key_ops")
		_, err = obj.ComputeAndEncode(macer, nil)
		assert.ErrorContains(err, "invalid key_ops")
		macer.Key().SetOps(iana.KeyOperationMacCreate)
		assert.NoError(obj.Compute(macer, nil))
		tag := obj.Tag()

		macer.Key().SetOps(iana.KeyOperationMacCreate)
		assert.ErrorContains(obj.Verify(macer, nil), "invalid key_ops")

		macer.Key().SetOps(iana.KeyOperationMacVerify)
		assert.NoError(obj.Verify(macer, nil))

		data1, err := obj.MarshalCBOR()
		require.NoError(t, err)
		data2, err := key.MarshalCBOR(obj)
		require.NoError(t, err)
		assert.Equal(data1, data2)

		var obj1 Mac0Message[[]byte]
		assert.NoError(key.UnmarshalCBOR(data1, &obj1))
		assert.NoError(obj1.Verify(macer, nil))
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(tag, obj1.Tag())

		_, err = VerifyMac0Message[[]byte](macer, data2[5:], nil)
		assert.ErrorContains(err, "cbor: ")
		obj2, err := VerifyMac0Message[[]byte](macer, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(tag, obj2.Tag())

		data2 = append(cwtPrefix, data2...)
		obj2, err = VerifyMac0Message[[]byte](macer, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(tag, obj2.Tag())
		assert.NotEqual(data2, obj2.Bytesify())

		data2 = RemoveCBORTag(data2)
		obj2, err = VerifyMac0Message[[]byte](macer, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(tag, obj2.Tag())
		assert.NotEqual(data2, obj2.Bytesify())
	})

	t.Run("payload cbor.RawMessage", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesmac.GenerateKey(iana.AlgorithmAES_MAC_128_128)
		require.NoError(t, err)

		macer, err := k.MACer()
		require.NoError(t, err)

		obj := &Mac0Message[cbor.RawMessage]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_64},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		assert.ErrorContains(obj.Compute(macer, nil),
			`macer'alg mismatch, expected 4, got 25`)
		_, err = obj.ComputeAndEncode(macer, nil)
		assert.ErrorContains(err,
			`macer'alg mismatch, expected 4, got 25`)

		obj.Protected[iana.HeaderParameterAlg] = iana.AlgorithmAES_MAC_128_128
		data, err := obj.ComputeAndEncode(macer, nil)
		require.NoError(t, err)
		tag := obj.Tag()

		k1, err := aesmac.GenerateKey(iana.AlgorithmAES_MAC_128_64)
		require.NoError(t, err)
		macer1, err := k1.MACer()
		require.NoError(t, err)
		_, err = VerifyMac0Message[cbor.RawMessage](macer1, data, nil)
		assert.ErrorContains(err,
			`macer'alg mismatch, expected 25, got 14`)

		obj1, err := VerifyMac0Message[cbor.RawMessage](macer, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(tag, obj1.Tag())
		assert.Equal(data, obj1.Bytesify())
	})

	t.Run("payload T", func(t *testing.T) {
		assert := assert.New(t)

		k, err := hmac.GenerateKey(iana.AlgorithmHMAC_512_512)
		require.NoError(t, err)

		macer, err := k.MACer()
		require.NoError(t, err)

		type T struct {
			Str string
		}

		obj := &Mac0Message[T]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_512_512},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     T{"This is the content."},
		}

		data, err := obj.ComputeAndEncode(macer, nil)
		require.NoError(t, err)
		tag := obj.Tag()

		obj1, err := VerifyMac0Message[T](macer, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload.Str, obj1.Payload.Str)
		assert.Equal(tag, obj1.Tag())
		assert.Equal(data, obj1.Bytesify())

		_, err = VerifyMac0Message[Headers](macer, data, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae := make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[4])
		datae[4] = 0x60
		_, err = VerifyMac0Message[T](macer, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[7])
		datae[7] = 0x60
		_, err = VerifyMac0Message[T](macer, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		obj = &Mac0Message[T]{
			Protected: Headers{
				iana.HeaderParameterAlg:      iana.AlgorithmHMAC_512_512,
				iana.HeaderParameterReserved: func() {},
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: T{"This is the content."},
		}

		_, err = obj.ComputeAndEncode(macer, nil)
		assert.ErrorContains(err, "unsupported type: func()")

		obje := &Mac0Message[func()]{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmHMAC_512_512,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: func() {},
		}

		_, err = obje.ComputeAndEncode(macer, nil)
		assert.ErrorContains(err, "unsupported type: func()")
	})
}
