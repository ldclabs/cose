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
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/ed25519"
)

func TestSign1(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/sign1-tests
	for _, tc := range []struct {
		title       string
		key         key.Key
		protected   Headers
		unprotected Headers
		payload     []byte
		external    []byte
		toSign      []byte
		output      []byte
		removeTag   bool
	}{
		{
			`sign-pass-01: Redo protected`,
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    []byte("11"), //  h'3131'
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
				iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
				iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
			},
			Headers{},
			Headers{
				iana.HeaderParameterKid: []byte("11"),
				iana.HeaderParameterAlg: iana.AlgorithmES256,
			},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("846A5369676E617475726531404054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F"),
			false,
		},
		{
			`sign-pass-02: External`,
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    []byte("11"), //  h'3131'
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
				iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
				iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmES256,
			},
			Headers{
				iana.HeaderParameterKid: []byte("11"),
			},
			[]byte("This is the content."),
			key.HexBytesify("11aa22bb33cc44dd55006699"),
			key.HexBytesify("846A5369676E61747572653143A101264C11AA22BB33CC44DD5500669954546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B"),
			false,
		},
		{
			`sign-pass-03: Remove CBOR Tag`,
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    []byte("11"), //  h'3131'
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
				iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
				iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmES256,
			},
			Headers{
				iana.HeaderParameterKid: []byte("11"),
			},
			[]byte("This is the content."),
			nil,
			key.HexBytesify("846A5369676E61747572653143A101264054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("8443A10126A10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36"),
			true,
		},
	} {
		signer, err := tc.key.Signer()
		require.NoError(t, err, tc.title)

		verifier, err := tc.key.Verifier()
		require.NoError(t, err, tc.title)

		obj := &Sign1Message[[]byte]{
			Protected:   tc.protected,
			Unprotected: tc.unprotected,
			Payload:     tc.payload,
		}
		err = obj.WithSign(signer, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toSign, obj.toSign, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		assert.NotEqual(tc.output, output, tc.title)

		var obj2 Sign1Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(output, &obj2), tc.title)
		require.NoError(t, obj2.Verify(verifier, tc.external), tc.title)
		assert.Equal(tc.toSign, obj2.toSign, tc.title)
		assert.Equal(obj.Signature(), obj2.Signature(), tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.payload, obj2.Payload, tc.title)

		if tc.title == "sign-pass-01: Redo protected" {
			continue
			// t.Skip("TODO: bad case?")
			// https://github.com/cose-wg/Examples/issues/107
		}

		var obj3 Sign1Message[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj3), tc.title)
		require.NoError(t, obj3.Verify(verifier, tc.external), tc.title)
		assert.Equal(tc.toSign, obj3.toSign, tc.title)
		assert.NotEqual(obj.Signature(), obj3.Signature(), tc.title)
		assert.Equal(tc.payload, obj3.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj3.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj3.Bytesify(), tc.title)
		}

		obj4, err := VerifySign1Message[[]byte](verifier, tc.output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toSign, obj4.toSign, tc.title)
		assert.NotEqual(obj.Signature(), obj4.Signature(), tc.title)
		assert.Equal(tc.payload, obj4.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj4.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj4.Bytesify(), tc.title)
		}

		output, err = obj4.SignAndEncode(signer, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toSign, obj4.toSign, tc.title)
		assert.NotEqual(obj.Signature(), obj4.Signature(), tc.title)

		obj4, err = VerifySign1Message[[]byte](verifier, output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toSign, obj4.toSign, tc.title)
		assert.NotEqual(obj.Signature(), obj4.Signature(), tc.title)
		assert.Equal(tc.payload, obj4.Payload, tc.title)
	}
}

func TestSign1EdgeCase(t *testing.T) {
	t.Run("common edge case", func(t *testing.T) {
		assert := assert.New(t)

		k, err := ed25519.GenerateKey()
		require.NoError(t, err)

		signer, err := k.Signer()
		require.NoError(t, err)

		verifier, err := k.Verifier()
		require.NoError(t, err)

		var obj *Sign1Message[[]byte]
		assert.ErrorContains(obj.UnmarshalCBOR([]byte{0x84}), "nil Sign1Message")

		obj = &Sign1Message[[]byte]{
			Payload: []byte("This is the content."),
		}
		assert.ErrorContains(obj.Verify(verifier, nil), "should call Sign1Message.UnmarshalCBOR")

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "should call Sign1Message.WithSign")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "should call Sign1Message.WithSign")

		assert.Nil(obj.Bytesify())
		assert.Nil(obj.Signature())

		signer.Key().SetOps(iana.KeyOperationVerify)
		assert.ErrorContains(obj.WithSign(signer, nil), "invalid key_ops")
		_, err = obj.SignAndEncode(signer, nil)
		assert.ErrorContains(err, "invalid key_ops")
		signer.Key().SetOps(iana.KeyOperationSign)
		assert.NoError(obj.WithSign(signer, nil))
		sig := obj.Signature()

		verifier.Key().SetOps(iana.KeyOperationSign)
		assert.ErrorContains(obj.Verify(verifier, nil), "invalid key_ops")

		verifier.Key().SetOps(iana.KeyOperationVerify)
		assert.NoError(obj.Verify(verifier, nil))

		data1, err := obj.MarshalCBOR()
		require.NoError(t, err)
		data2, err := key.MarshalCBOR(obj)
		require.NoError(t, err)
		assert.Equal(data1, data2)

		var obj1 Sign1Message[[]byte]
		assert.NoError(key.UnmarshalCBOR(data1, &obj1))
		assert.NoError(obj1.Verify(verifier, nil))
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(sig, obj1.Signature())

		_, err = VerifySign1Message[[]byte](verifier, data2[5:], nil)
		assert.ErrorContains(err, "cbor: ")
		obj2, err := VerifySign1Message[[]byte](verifier, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(sig, obj2.Signature())

		data2 = append(cwtPrefix, data2...)
		obj2, err = VerifySign1Message[[]byte](verifier, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(sig, obj2.Signature())
		assert.NotEqual(data2, obj2.Bytesify())

		data2 = RemoveCBORTag(data2)
		obj2, err = VerifySign1Message[[]byte](verifier, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(sig, obj2.Signature())
		assert.NotEqual(data2, obj2.Bytesify())
	})

	t.Run("payload cbor.RawMessage", func(t *testing.T) {
		assert := assert.New(t)

		k, err := ecdsa.GenerateKey(iana.AlgorithmES256)
		require.NoError(t, err)

		signer, err := k.Signer()
		require.NoError(t, err)

		verifier, err := k.Verifier()
		require.NoError(t, err)

		obj := &Sign1Message[cbor.RawMessage]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmEdDSA},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		assert.ErrorContains(obj.WithSign(signer, nil),
			`signer'alg mismatch, expected -8, got -7`)
		_, err = obj.SignAndEncode(signer, nil)
		assert.ErrorContains(err,
			`signer'alg mismatch, expected -8, got -7`)

		obj.Protected[iana.HeaderParameterAlg] = iana.AlgorithmES256
		data, err := obj.SignAndEncode(signer, nil)
		require.NoError(t, err)
		sig := obj.Signature()

		k1, err := ecdsa.GenerateKey(iana.AlgorithmES384)
		require.NoError(t, err)
		verifier1, err := k1.Verifier()
		require.NoError(t, err)
		_, err = VerifySign1Message[cbor.RawMessage](verifier1, data, nil)
		assert.ErrorContains(err,
			`verifier'alg mismatch, expected -7, got -35`)

		obj1, err := VerifySign1Message[cbor.RawMessage](verifier, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(sig, obj1.Signature())
		assert.Equal(data, obj1.Bytesify())
	})

	t.Run("payload T", func(t *testing.T) {
		assert := assert.New(t)

		k, err := ed25519.GenerateKey()
		require.NoError(t, err)

		signer, err := k.Signer()
		require.NoError(t, err)

		verifier, err := k.Verifier()
		require.NoError(t, err)

		type T struct {
			Str string
		}

		obj := &Sign1Message[T]{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmEdDSA,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: T{"This is the content."},
		}

		data, err := obj.SignAndEncode(signer, nil)
		require.NoError(t, err)
		sig := obj.Signature()

		obj1, err := VerifySign1Message[T](verifier, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload.Str, obj1.Payload.Str)
		assert.Equal(sig, obj1.Signature())
		assert.Equal(data, obj1.Bytesify())

		_, err = VerifySign1Message[Headers](verifier, data, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae := make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[4])
		datae[4] = 0x60
		_, err = VerifySign1Message[T](verifier, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[7])
		datae[7] = 0x60
		_, err = VerifySign1Message[T](verifier, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x53), datae[33]) // "S"
		datae[33] = 0xfa
		_, err = VerifySign1Message[T](verifier, datae, nil)
		assert.ErrorContains(err, "invalid UTF-8 string")

		obj = &Sign1Message[T]{
			Protected: Headers{
				iana.HeaderParameterAlg:      iana.AlgorithmEdDSA,
				iana.HeaderParameterReserved: func() {},
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: T{"This is the content."},
		}

		_, err = obj.SignAndEncode(signer, nil)
		assert.ErrorContains(err, "unsupported type: func()")

		obje := &Sign1Message[func()]{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmEdDSA,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: func() {},
		}

		_, err = obje.SignAndEncode(signer, nil)
		assert.ErrorContains(err, "unsupported type: func()")
	})
}
