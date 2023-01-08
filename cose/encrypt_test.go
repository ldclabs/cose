// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"crypto/elliptic"
	"testing"

	"github.com/aead/ecdh"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/aesccm"
	"github.com/ldclabs/cose/key/aesgcm"
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/hkdf"
)

func TestEncryptMessage(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/enveloped-tests
	// https://github.com/cose-wg/Examples/tree/master/RFC8152
	for _, tc := range []struct {
		title       string
		key         key.Key
		protected   Headers
		unprotected Headers
		plaintext   []byte
		recipients  []*Recipient
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
			key.HexBytesify("0011bbcc22dd4455dd220099"),
			key.HexBytesify("8367456E637279707443A101014C0011BBCC22DD4455DD220099"),
			key.HexBytesify("D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B7CDE42D4F7E6DD896E231C71FDD6FC99818340A20125044A6F75722D73656372657440"),
			false,
		},
		{
			`env-pass-03: Remove leading CBOR tag`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			},
			Headers{},
			Headers{
				iana.HeaderParameterIV:  key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
				iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
			},
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
			key.HexBytesify("8367456E63727970744040"),
			key.HexBytesify("8440A20101054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B9874993C63B0382A855573F0990CD18E818340A20125044A6F75722D73656372657440"),
			true,
		},
		{
			`AES-GCM-01: Encryption example for spec - `,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
			},
			Headers{
				iana.HeaderParameterIV: key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
			},
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
			key.HexBytesify("8367456E637279707443A1010140"),
			key.HexBytesify("D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73656372657440"),
			false,
		},
		{
			`Encryption example for spec - Direct ECDH`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.HexBytesify("56074D506729CA40C4B4FE50C6439893"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
			},
			Headers{
				iana.HeaderParameterIV: key.HexBytesify("C9CF4DF2FE6C632BF7886413"),
			},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
					},
					Unprotected: Headers{
						iana.HeaderAlgorithmParameterEphemeralKey: key.Key{
							iana.KeyParameterKty:    iana.KeyTypeEC2,
							iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
							iana.EC2KeyParameterX:   key.HexBytesify("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280"),
							iana.EC2KeyParameterY:   true,
						},
						iana.HeaderParameterKid: []byte("meriadoc.brandybuck@buckland.example"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("8367456E637279707443A1010140"),
			key.HexBytesify("D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A20458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6520A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D628022F540"),
			false,
		},
		{
			`Encryption example for spec - Direct ECDH 2`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("C3B3584E0EC878C041281299EBE60D98"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmAES_CCM_16_64_128,
			},
			Headers{
				iana.HeaderParameterIV: key.HexBytesify("89F52F65A1C580933B5261A76C"),
			},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmDirect_HKDF_SHA_256,
					},
					Unprotected: Headers{
						iana.HeaderAlgorithmParameterSalt: key.HexBytesify("61616262636364646565666667676868"),
						iana.HeaderParameterKid:           []byte("our-secret"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("8367456E637279707443A1010A40"),
			key.HexBytesify("D8608443A1010AA1054D89F52F65A1C580933B5261A76C581C753548A19B1307084CA7B2056924ED95F2E3B17006DFE931B687B847818343A10129A2044A6F75722D73656372657433506161626263636464656566666767686840"),
			false,
		},
		{
			`Encryption example for spec - Direct ECDH 3`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.HexBytesify("56074D506729CA40C4B4FE50C6439893"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
			},
			Headers{
				iana.HeaderParameterIV: key.HexBytesify("C9CF4DF2FE6C632BF7886413"),
				iana.HeaderParameterCounterSignature: Signature{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmES512,
					},
					Unprotected: Headers{
						iana.HeaderParameterKid: []byte("bilbo.baggins@hobbiton.example"),
					},
					Signature: key.HexBytesify("00929663C8789BB28177AE28467E66377DA12302D7F9594D2999AFA5DFA531294F8896F2B6CDF1740014F4C7F1A358E3A6CF57F4ED6FB02FCF8F7AA989F5DFD07F0700A3A7D8F3C604BA70FA9411BD10C2591B483E1D2C31DE003183E434D8FBA18F17A4C7E3DFA003AC1CF3D30D44D2533C4989D3AC38C38B71481CC3430C9D65E7DDFF"),
				},
			},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
					},
					Unprotected: Headers{
						iana.HeaderAlgorithmParameterEphemeralKey: key.Key{
							iana.KeyParameterKty:    iana.KeyTypeEC2,
							iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
							iana.EC2KeyParameterX:   key.HexBytesify("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280"),
							iana.EC2KeyParameterY:   true,
						},
						iana.HeaderParameterKid: []byte("meriadoc.brandybuck@buckland.example"),
					},
					Ciphertext: []byte{},
				},
			},
			nil,
			key.HexBytesify("8367456E637279707443A1010140"),
			key.HexBytesify("D8608443A10101A2054CC9CF4DF2FE6C632BF7886413078344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65588400929663C8789BB28177AE28467E66377DA12302D7F9594D2999AFA5DFA531294F8896F2B6CDF1740014F4C7F1A358E3A6CF57F4ED6FB02FCF8F7AA989F5DFD07F0700A3A7D8F3C604BA70FA9411BD10C2591B483E1D2C31DE003183E434D8FBA18F17A4C7E3DFA003AC1CF3D30D44D2533C4989D3AC38C38B71481CC3430C9D65E7DDFF58247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A20458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6520A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D628022F540"),
			false,
		},
		{
			`ENC-06: Encryption example for spec - Direct ECDH + A128 Key Wrap`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        []byte("our-secret"),
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.HexBytesify("B2353161740AACF1F7163647984B522A"),
			},
			Headers{
				iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
			},
			Headers{
				iana.HeaderParameterIV: key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
			},
			[]byte("This is the content."),
			[]*Recipient{
				{
					Protected: Headers{
						iana.HeaderParameterAlg: iana.AlgorithmECDH_SS_A128KW,
					},
					Unprotected: Headers{
						iana.HeaderAlgorithmParameterStaticKeyId: []byte("peregrin.took@tuckborough.example"),
						iana.HeaderParameterKid:                  []byte("meriadoc.brandybuck@buckland.example"),
						iana.HeaderAlgorithmParameterPartyUNonce: key.HexBytesify("0101"),
					},
					Ciphertext: key.HexBytesify("41E0D76F579DBD0D936A662D54D8582037DE2E366FDE1C62"),
				},
			},
			key.HexBytesify("0011bbcc22dd44ee55ff660077"),
			key.HexBytesify("8367456E637279707443A101014D0011BBCC22DD44EE55FF660077"),
			key.HexBytesify("D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E28529D8F5335E5F0165EEE976B4A5F6C6F09D818344A101381FA30458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65225821706572656772696E2E746F6F6B407475636B626F726F7567682E6578616D706C6535420101581841E0D76F579DBD0D936A662D54D8582037DE2E366FDE1C62"),
			false,
		},
	} {
		encryptor, err := tc.key.Encryptor()
		require.NoError(t, err, tc.title)

		obj := &EncryptMessage[[]byte]{
			Protected:   tc.protected,
			Unprotected: tc.unprotected,
			Payload:     tc.plaintext,
		}
		for _, r := range tc.recipients {
			obj.AddRecipient(r)
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

		var obj2 EncryptMessage[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj2), tc.title)
		require.NoError(t, obj2.Decrypt(encryptor, tc.external), tc.title)
		// verify repeatedly should ok
		require.NoError(t, obj2.Decrypt(encryptor, tc.external), tc.title)
		assert.Equal(tc.toEnc, obj2.toEnc, tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.plaintext, obj2.Payload, tc.title)

		var obj3 EncryptMessage[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj3), tc.title)
		require.NoError(t, obj3.Decrypt(encryptor, tc.external), tc.title)
		assert.Equal(tc.toEnc, obj3.toEnc, tc.title)
		assert.Equal(tc.plaintext, obj3.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj3.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj3.Bytesify(), tc.title)
		}

		obj4, err := DecryptEncryptMessage[[]byte](encryptor, tc.output, tc.external)
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

		obj4, err = DecryptEncryptMessage[[]byte](encryptor, output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj4.toEnc, tc.title)
		assert.Equal(tc.plaintext, obj4.Payload, tc.title)
	}
}

func TestEncryptMessageEdgeCase(t *testing.T) {
	t.Run("common edge case", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesgcm.GenerateKey(0)
		require.NoError(t, err)

		encryptor, err := k.Encryptor()
		require.NoError(t, err)

		var obj *EncryptMessage[[]byte]
		assert.ErrorContains(obj.UnmarshalCBOR([]byte{0x84}), "nil EncryptMessage")

		obj = &EncryptMessage[[]byte]{
			Payload: []byte("This is the content."),
		}
		assert.ErrorContains(obj.Decrypt(encryptor, nil), "should call EncryptMessage.UnmarshalCBOR")

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "should call EncryptMessage.Encrypt")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "should call EncryptMessage.Encrypt")

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
		assert.Equal(byte(0x81), data1[82])

		var obj1 EncryptMessage[[]byte]
		data := make([]byte, 83)
		copy(data, data1)
		data[82] = 0x80
		assert.ErrorContains(key.UnmarshalCBOR(data, &obj1), "no recipients")

		data = make([]byte, 84)
		copy(data, data1)
		data[82] = 0x81
		data[83] = 0xf6
		assert.ErrorContains(key.UnmarshalCBOR(data, &obj1), "nil Recipient")

		assert.NoError(key.UnmarshalCBOR(data1, &obj1))
		assert.NoError(obj1.Decrypt(encryptor, nil))
		assert.Equal(obj.Payload, obj1.Payload)

		_, err = DecryptEncryptMessage[[]byte](encryptor, data2[5:], nil)
		assert.ErrorContains(err, "cbor: cannot unmarshal")
		obj2, err := DecryptEncryptMessage[[]byte](encryptor, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)

		data2 = append(cwtPrefix, data2...)
		obj2, err = DecryptEncryptMessage[[]byte](encryptor, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.NotEqual(data2, obj2.Bytesify())

		data2 = RemoveCBORTag(data2)
		obj2, err = DecryptEncryptMessage[[]byte](encryptor, data2, nil)
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

		obj := &EncryptMessage[cbor.RawMessage]{
			Unprotected: Headers{iana.HeaderParameterIV: iv[2:]},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		obj.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})
		assert.ErrorContains(obj.Encrypt(encryptor, nil),
			`invalid nonce size, expected 12, got 10`)
		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err,
			`invalid nonce size, expected 12, got 10`)

		obj.Unprotected[iana.HeaderParameterIV] = iv
		data, err := obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		obj1, err := DecryptEncryptMessage[cbor.RawMessage](encryptor2, data, nil)
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

		encryptor.Key()[iana.KeyParameterBaseIV] = iv[:8]
		assert.NoError(obj.Encrypt(encryptor, nil))
		data, err = obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		obj1 = &EncryptMessage[cbor.RawMessage]{}
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
	})

	t.Run("payload cbor.RawMessage", func(t *testing.T) {
		assert := assert.New(t)

		k, err := aesgcm.GenerateKey(iana.AlgorithmA256GCM)
		require.NoError(t, err)

		encryptor, err := k.Encryptor()
		require.NoError(t, err)

		obj := &EncryptMessage[cbor.RawMessage]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmA192GCM},
			Unprotected: Headers{iana.HeaderParameterKid: k.Kid()},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}
		obj.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})
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
		_, err = DecryptEncryptMessage[cbor.RawMessage](encryptor1, data, nil)
		assert.ErrorContains(err,
			`encryptor'alg mismatch, expected 3, got 2`)

		obj1, err := DecryptEncryptMessage[cbor.RawMessage](encryptor, data, nil)
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

		obj := &EncryptMessage[T]{
			Protected:   Headers{iana.HeaderParameterAlg: iana.AlgorithmAES_CCM_64_64_256},
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

		data, err := obj.EncryptAndEncode(encryptor, nil)
		require.NoError(t, err)

		obj1, err := DecryptEncryptMessage[T](encryptor, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload.Str, obj1.Payload.Str)
		assert.Equal(data, obj1.Bytesify())

		datae := make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[5])
		datae[5] = 0x60
		_, err = DecryptEncryptMessage[T](encryptor, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[8])
		datae[8] = 0x60
		_, err = DecryptEncryptMessage[T](encryptor, datae, nil)
		assert.ErrorContains(err, "cannot unmarshal UTF-8 text string")

		obj = &EncryptMessage[T]{
			Protected: Headers{
				iana.HeaderParameterAlg:      iana.AlgorithmAES_CCM_64_64_256,
				iana.HeaderParameterReserved: func() {},
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: k.Kid(),
			},
			Payload: T{"This is the content."},
		}
		obj.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		})

		_, err = obj.EncryptAndEncode(encryptor, nil)
		assert.ErrorContains(err, "unsupported type: func()")

		obje := &EncryptMessage[func()]{
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

func TestEncryptMessageECDH(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/RFC8152
	for _, tc := range []struct {
		title     string
		keyS      key.Key
		keyR      key.Key
		cek       []byte
		iv        []byte
		plaintext []byte
		context   []byte
		toEnc     []byte
		output    []byte
	}{
		{
			`Encryption example for spec - Direct ECDH`,
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    []byte("meriadoc.brandybuck@buckland.example"),
				iana.KeyParameterAlg:    iana.AlgorithmES256,
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   key.Base64Bytesify("mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA"),
				iana.EC2KeyParameterY:   key.Base64Bytesify("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs"),
			},
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    []byte("meriadoc.brandybuck@buckland.example"),
				iana.KeyParameterAlg:    iana.AlgorithmES256,
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   key.Base64Bytesify("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
				iana.EC2KeyParameterY:   key.Base64Bytesify("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
				iana.EC2KeyParameterD:   key.Base64Bytesify("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"),
			},
			key.HexBytesify("56074D506729CA40C4B4FE50C6439893"),
			key.HexBytesify("C9CF4DF2FE6C632BF7886413"),
			[]byte("This is the content."),
			key.HexBytesify("840183F6F6F683F6F6F682188044A1013818"),
			key.HexBytesify("8367456E637279707443A1010140"),
			key.HexBytesify("D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A20458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6520A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D628022F5F6"),
		},
	} {
		kdfContext := KDFContext{
			AlgorithmID: iana.AlgorithmA128GCM,
			SuppPubInfo: SuppPubInfo{
				KeyDataLength: 128,
				Protected: Headers{
					iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
				},
			},
		}
		ctxData, err := key.MarshalCBOR(kdfContext)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.context, ctxData, tc.title)

		p256 := ecdh.Generic(elliptic.P256())

		privK, err := tc.keyR.GetBytes(iana.EC2KeyParameterD)
		require.NoError(t, err, tc.title)
		pubK, err := ecdsa.KeyToPublic(tc.keyS)
		require.NoError(t, err, tc.title)
		secret := p256.ComputeSecret(privK, ecdh.Point{X: pubK.X, Y: pubK.Y})

		cek, err := hkdf.HKDF256(secret, nil, ctxData, 128/8)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.cek, cek, tc.title)

		gcmkey, err := aesgcm.KeyFrom(iana.AlgorithmA128GCM, cek)
		require.NoError(t, err, tc.title)

		encryptor, err := gcmkey.Encryptor()
		require.NoError(t, err, tc.title)

		obj := &EncryptMessage[[]byte]{
			Unprotected: Headers{iana.HeaderParameterIV: tc.iv},
			Payload:     tc.plaintext,
		}

		err = obj.Encrypt(encryptor, nil)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.toEnc, obj.toEnc, tc.title)

		ck, err := ecdsa.ToCompressedKey(tc.keyS)
		require.NoError(t, err, tc.title)
		rp := &Recipient{
			Protected: Headers{iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256},
			Unprotected: Headers{
				iana.HeaderAlgorithmParameterEphemeralKey: ck,
				iana.HeaderParameterKid:                   []byte("meriadoc.brandybuck@buckland.example"),
			},
		}
		err = obj.AddRecipient(rp)
		require.NoError(t, err, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		// fmt.Printf("Output: %X\n", output)
		assert.Equal(tc.output, output, tc.title)

		var obj2 EncryptMessage[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj2), tc.title)
		require.NoError(t, obj2.Decrypt(encryptor, nil), tc.title)
		assert.Equal(tc.toEnc, obj2.toEnc, tc.title)
		// fmt.Printf("Output: %X\n", obj2.Bytesify())
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.plaintext, obj2.Payload, tc.title)
	}
}
