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
	"github.com/ldclabs/cose/key/aesmac"
	"github.com/ldclabs/cose/key/hmac"
)

func TestMac(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/mac0-tests
	// https://github.com/cose-wg/Examples/tree/master/RFC8152
	for _, tc := range []struct {
		title       string
		key         key.Key
		protected   Headers
		unprotected Headers
		payload     []byte
		recipients  []*Recipient
		external    []byte
		toMac       []byte
		output      []byte
		removeTag   bool
	}{
		{
			`mac-pass-02: External Data`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{},
					Unprotected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmDirect,
						iana.HeaderParameterKid: []byte("our-secret"),
					},
					Ciphertext: []byte{},
				},
			},
			key.HexBytesify("11aa22bb33cc44dd55006699"),
			key.HexBytesify("84634D4143404C11AA22BB33CC44DD5500669954546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D8618540A1010554546869732069732074686520636F6E74656E742E582060CFE7D9C733A758E198FF758A381E43B3CAF9867AEBAEF224CA8F11FFD3AC7A818340A20125044A6F75722D73656372657440"),
			false,
		},
		{
			`mac-pass-03: remvove cbor tag`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{},
					Unprotected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmDirect,
						iana.HeaderParameterKid: []byte("our-secret"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("84634D4143404054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("8540A1010554546869732069732074686520636F6E74656E742E5820C2EBE664C1D996AA3026824BBBB7CAA454E2CC4212181AD9F34C7879CBA1972E818340A20125044A6F75722D73656372657440"),
			true,
		},
		{
			`HMAC-01: Direct key + HMAC-SHA256`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			Headers{},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{},
					Unprotected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmDirect,
						iana.HeaderParameterKid: []byte("our-secret"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("84634D414343A101054054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440"),
			false,
		},
		{
			`MAC example with direct shared key and AES-CMAC/64`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_256_64,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmAES_MAC_256_64},
			Headers{},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{},
					Unprotected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmDirect,
						iana.HeaderParameterKid: []byte("our-secret"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("84634D414343A1010F4054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D8618543A1010FA054546869732069732074686520636F6E74656E742E489E1226BA1F81B848818340A20125044A6F75722D73656372657440"),
			false,
		},
		{
			`MAC example with direct ECDH static-static and HMAC-SHA256`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("1C86606741D3C5C7683BD8767B5A6E6D7DDA6735C76DF3E885546E4BDCA838AB"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			Headers{},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmECDH_SS_HKDF_256,
					},
					Unprotected: Headers{
						iana.HeaderParameterKid:                  []byte("meriadoc.brandybuck@buckland.example"),
						iana.HeaderAlgorithmParameterStaticKeyId: []byte("peregrin.took@tuckborough.example"),
						iana.HeaderAlgorithmParameterPartyUNonce: key.HexBytesify("4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("84634D414343A101054054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D8618543A10105A054546869732069732074686520636F6E74656E742E582081A03448ACD3D305376EAA11FB3FE416A955BE2CBE7EC96F012C994BC3F16A41818344A101381AA30458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65225821706572656772696E2E746F6F6B407475636B626F726F7567682E6578616D706C653558404D8553E7E74F3C6A3A9DD3EF286A8195CBF8A23D19558CCFEC7D34B824F42D92BD06BD2C7F0271F0214E141FB779AE2856ABF585A58368B017E7F2A9E5CE4DB540"),
			false,
		},
		{
			`MAC example with AES Keywrap from a direct shared secret and AES-128-CBC-MAC-64`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
				iana.SymmetricKeyParameterK: key.HexBytesify("DDDC08972DF9BE62855291A17A1B4CF7"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmAES_MAC_128_64},
			Headers{},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{},
					Unprotected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmA256KW,
						iana.HeaderParameterKid: []byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037"),
					},
					Ciphertext: key.HexBytesify("711AB0DC2FC4585DCE27EFFA6781C8093EBA906F227B6EB0"),
				},
			},
			nil,
			key.HexBytesify("84634D414343A1010E4054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A2012404582430313863306165352D346439622D343731622D626664362D6565663331346263373033375818711AB0DC2FC4585DCE27EFFA6781C8093EBA906F227B6EB0"),
			false,
		},
		{
			`MAC example with multiple recipients`,
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("2B7459201E5046E33FDB514C5E14A1B01D9893F8936335F821FCB1AFF450B226"),
			},
			Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_256_256},
			Headers{},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_A128KW,
					},
					Unprotected: Headers{
						iana.HeaderAlgorithmParameterEphemeralKey: key.Key{
							iana.KeyParameterKty:    iana.KeyTypeEC2,
							iana.EC2KeyParameterCrv: iana.EllipticCurveP_521,
							iana.EC2KeyParameterX:   key.HexBytesify("0043B12669ACAC3FD27898FFBA0BCD2E6C366D53BC4DB71F909A759304ACFB5E18CDC7BA0B13FF8C7636271A6924B1AC63C02688075B55EF2D613574E7DC242F79C3"),
							iana.EC2KeyParameterY:   true,
						},
						iana.HeaderParameterKid: []byte("bilbo.baggins@hobbiton.example"),
					},
					Ciphertext: key.HexBytesify("339BC4F79984CDC6B3E6CE5F315A4C7D2B0AC466FCEA69E8C07DFBCA5BB1F661BC5F8E0DF9E3EFF5"),
				},
				{
					Protected: Headers{},
					Unprotected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmA256KW,
						iana.HeaderParameterKid: []byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037"),
					},
					Ciphertext: key.HexBytesify("0B2C7CFCE04E98276342D6476A7723C090DFDD15F9A518E7736549E998370695E6D6A83B4AE507BB"),
				},
			},
			nil,
			key.HexBytesify("84634D414343A101054054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("D8618543A10105A054546869732069732074686520636F6E74656E742E5820BF48235E809B5C42E995F2B7D5FA13620E7ED834E337F6AA43DF161E49E9323E828344A101381CA204581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C6520A4010220032158420043B12669ACAC3FD27898FFBA0BCD2E6C366D53BC4DB71F909A759304ACFB5E18CDC7BA0B13FF8C7636271A6924B1AC63C02688075B55EF2D613574E7DC242F79C322F55828339BC4F79984CDC6B3E6CE5F315A4C7D2B0AC466FCEA69E8C07DFBCA5BB1F661BC5F8E0DF9E3EFF58340A2012404582430313863306165352D346439622D343731622D626664362D65656633313462633730333758280B2C7CFCE04E98276342D6476A7723C090DFDD15F9A518E7736549E998370695E6D6A83B4AE507BB"),
			false,
		},
	} {
		macer, err := tc.key.MACer()
		require.NoError(t, err, tc.title)

		obj := &MacMessage[[]byte]{
			Protected:   tc.protected,
			Unprotected: tc.unprotected,
			Payload:     tc.payload,
		}
		for _, r := range tc.recipients {
			obj.AddRecipient(r)
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

		var obj2 MacMessage[[]byte]
		require.NoError(t, key.UnmarshalCBOR(output, &obj2), tc.title)
		require.NoError(t, obj2.Verify(macer, tc.external), tc.title)
		// verify repeatedly should ok
		require.NoError(t, obj2.Verify(macer, tc.external), tc.title)
		assert.Equal(tc.toMac, obj2.toMac, tc.title)
		assert.Equal(obj.Tag(), obj2.Tag(), tc.title)
		assert.Equal(tc.payload, obj2.Payload, tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)

		var obj3 MacMessage[[]byte]
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

		obj4, err := VerifyMacMessage[[]byte](macer, tc.output, tc.external)
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

		obj4, err = VerifyMacMessage[[]byte](macer, output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toMac, obj4.toMac, tc.title)
		assert.Equal(obj.Tag(), obj4.Tag(), tc.title)
		assert.Equal(tc.payload, obj4.Payload, tc.title)
	}
}

func TestMacEdgeCase(t *testing.T) {
	t.Run("common edge case", func(t *testing.T) {
		assert := assert.New(t)

		k := key.Key{
			iana.KeyParameterKty:        iana.KeyTypeSymmetric,
			iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
			iana.KeyParameterKid:        []byte("11"),
			iana.SymmetricKeyParameterK: key.HexBytesify("DDDC08972DF9BE62855291A17A1B4CF7"),
		}

		macer, err := k.MACer()
		require.NoError(t, err)

		var obj *MacMessage[[]byte]
		assert.ErrorContains(obj.UnmarshalCBOR([]byte{0x84}), "nil MacMessage")

		obj = &MacMessage[[]byte]{
			Payload: []byte("This is the content."),
		}
		assert.ErrorContains(obj.Verify(macer, nil), "should call MacMessage.UnmarshalCBOR")

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "should call MacMessage.Compute")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "should call MacMessage.Compute")

		assert.Nil(obj.Bytesify())
		assert.Nil(obj.Tag())

		macer.Key().SetOps(iana.KeyOperationMacVerify)
		assert.ErrorContains(obj.Compute(macer, nil), "invalid key_ops")
		_, err = obj.ComputeAndEncode(macer, nil)
		assert.ErrorContains(err, "invalid key_ops")
		macer.Key().SetOps(iana.KeyOperationMacCreate)
		assert.NoError(obj.Compute(macer, nil))

		kid, err := obj.Unprotected.GetBytes(iana.HeaderParameterKid)
		require.NoError(t, err)
		assert.Equal(kid, []byte(k.Kid()))

		obj = &MacMessage[[]byte]{
			Unprotected: Headers{},
			Payload:     []byte("This is the content."),
		}
		assert.NoError(obj.Compute(macer, nil))
		kid, err = obj.Unprotected.GetBytes(iana.HeaderParameterKid)
		require.NoError(t, err)
		assert.Nil(kid)
		tag := obj.Tag()

		macer.Key().SetOps(iana.KeyOperationMacCreate)
		assert.ErrorContains(obj.Verify(macer, nil), "invalid key_ops")

		macer.Key().SetOps(iana.KeyOperationMacVerify)
		assert.NoError(obj.Verify(macer, nil))

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "no recipients")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "no recipients")

		assert.ErrorContains(obj.AddRecipient(nil), "nil Recipient")
		assert.Nil(obj.Recipients())
		obj.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})
		assert.Equal(1, len(obj.Recipients()))

		r := &Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		}
		r.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})
		assert.ErrorContains(obj.AddRecipient(r.Recipients()[0]),
			`should not have "Rec_Recipient" context`)

		data1, err := obj.MarshalCBOR()
		require.NoError(t, err)
		data2, err := key.MarshalCBOR(obj)
		require.NoError(t, err)
		assert.Equal(data1, data2)
		assert.Equal(byte(0x81), data1[38])

		var obj1 MacMessage[[]byte]
		data := make([]byte, 39)
		copy(data, data1)
		data[38] = 0x80
		assert.ErrorContains(key.UnmarshalCBOR(data, &obj1), "no recipients")

		data = make([]byte, 40)
		copy(data, data1)
		data[38] = 0x81
		data[39] = 0xf6
		assert.ErrorContains(key.UnmarshalCBOR(data, &obj1), "nil Recipient")

		assert.NoError(key.UnmarshalCBOR(data1, &obj1))
		assert.NoError(obj1.Verify(macer, nil))
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(tag, obj1.Tag())

		_, err = VerifyMacMessage[[]byte](macer, data2[5:], nil)
		assert.ErrorContains(err, "cbor: ")
		obj2, err := VerifyMacMessage[[]byte](macer, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(tag, obj2.Tag())

		data2 = append(cwtPrefix, data2...)
		obj2, err = VerifyMacMessage[[]byte](macer, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(tag, obj2.Tag())
		assert.NotEqual(data2, obj2.Bytesify())

		data2 = RemoveCBORTag(data2)
		obj2, err = VerifyMacMessage[[]byte](macer, data2, nil)
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

		obj := &MacMessage[cbor.RawMessage]{
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
		_, err = obj.ComputeAndEncode(macer, nil)
		assert.ErrorContains(err, "no recipients")
		obj.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})
		data, err := obj.ComputeAndEncode(macer, nil)
		require.NoError(t, err)
		tag := obj.Tag()

		k1, err := aesmac.GenerateKey(iana.AlgorithmAES_MAC_128_64)
		require.NoError(t, err)
		macer1, err := k1.MACer()
		require.NoError(t, err)
		_, err = VerifyMacMessage[cbor.RawMessage](macer1, data, nil)
		assert.ErrorContains(err,
			`macer'alg mismatch, expected 25, got 14`)

		obj1, err := VerifyMacMessage[cbor.RawMessage](macer, data, nil)
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

		obj := &MacMessage[T]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmHMAC_512_512},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     T{"This is the content."},
		}

		obj.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})
		data, err := obj.ComputeAndEncode(macer, nil)
		require.NoError(t, err)
		tag := obj.Tag()

		obj1, err := VerifyMacMessage[T](macer, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload.Str, obj1.Payload.Str)
		assert.Equal(tag, obj1.Tag())
		assert.Equal(data, obj1.Bytesify())

		obj2, err := VerifyMacMessage[Headers](macer, data, nil)
		require.NoError(t, err)
		assert.Equal(obj2.Payload.Get("Str"), "This is the content.")

		datae := make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[5])
		datae[5] = 0x40
		_, err = VerifyMacMessage[T](macer, datae, nil)
		assert.Error(err)

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[8])
		datae[8] = 0x40
		_, err = VerifyMacMessage[T](macer, datae, nil)
		assert.Error(err)

		obj = &MacMessage[T]{
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

		obje := &MacMessage[func()]{
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
