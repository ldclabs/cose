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
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/ed25519"
)

func TestSign(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/sign-tests
	for _, tc := range []struct {
		title       string
		ks          key.KeySet
		protected   Headers
		unprotected Headers
		payload     []byte
		external    []byte
		toSigns     [][]byte
		output      []byte
		removeTag   bool
	}{
		{
			`sign-pass-02: External`,
			key.KeySet{
				map[int]any{
					iana.KeyParameterKty:    iana.KeyTypeEC2,
					iana.KeyParameterKid:    []byte("11"), //  h'3131'
					iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
					iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
					iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
					iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
				},
			},
			nil,
			nil,
			[]byte("This is the content."),
			key.HexBytesify("11aa22bb33cc44dd55006699"),
			[][]byte{
				key.HexBytesify("85695369676E61747572654043A101264C11AA22BB33CC44DD5500669954546869732069732074686520636F6E74656E742E"),
			},
			key.HexBytesify("D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840CBB8DAD9BEAFB890E1A414124D8BFBC26BEDF2A94FCB5A882432BFF6D63E15F574EEB2AB51D83FA2CBF62672EBF4C7D993B0F4C2447647D831BA57CCA86B930A"),
			false,
		},
		{
			`sign-pass-03: Remove CBOR Tag`,
			key.KeySet{
				map[int]any{
					iana.KeyParameterKty:    iana.KeyTypeEC2,
					iana.KeyParameterKid:    []byte("11"), //  h'3131'
					iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
					iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
					iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
					iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
				},
			},
			nil,
			nil,
			[]byte("This is the content."),
			nil,
			[][]byte{
				key.HexBytesify("85695369676E61747572654043A101264054546869732069732074686520636F6E74656E742E"),
			},
			key.HexBytesify("8440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
			true,
		},
		{
			`Case: JOSE Cookbook Example 4.8 - multiple signatures`,
			key.KeySet{
				map[int]any{
					iana.KeyParameterKty:    iana.KeyTypeEC2,
					iana.KeyParameterKid:    []byte("11"), //  h'3131'
					iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
					iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
					iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
					iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
				},
				map[int]any{
					iana.KeyParameterKty:    iana.KeyTypeEC2,
					iana.KeyParameterKid:    []byte("bilbo.baggins@hobbiton.example"),
					iana.EC2KeyParameterCrv: iana.EllipticCurveP_521,
					iana.EC2KeyParameterX:   key.Base64Bytesify("cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0"),
					iana.EC2KeyParameterY:   key.Base64Bytesify("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
					iana.EC2KeyParameterD:   key.Base64Bytesify("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"),
				},
			},
			nil,
			nil,
			[]byte("This is the content."),
			nil,
			[][]byte{
				key.HexBytesify("85695369676E61747572654043A101264054546869732069732074686520636F6E74656E742E"),
				key.HexBytesify("85695369676E61747572654044A10138234054546869732069732074686520636F6E74656E742E"),
			},
			key.HexBytesify("D8628440A054546869732069732074686520636F6E74656E742E828343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A8344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65588400A2D28A7C2BDB1587877420F65ADF7D0B9A06635DD1DE64BB62974C863F0B160DD2163734034E6AC003B01E8705524C5C4CA479A952F0247EE8CB0B4FB7397BA08D009E0C8BF482270CC5771AA143966E5A469A09F613488030C5B07EC6D722E3835ADB5B2D8C44E95FFB13877DD2582866883535DE3BB03D01753F83AB87BB4F7A0297"),
			false,
		},
	} {
		signers, err := tc.ks.Signers()
		require.NoError(t, err, tc.title)

		verifiers, err := tc.ks.Verifiers()
		require.NoError(t, err, tc.title)

		obj := &SignMessage[[]byte]{
			Protected:   tc.protected,
			Unprotected: tc.unprotected,
			Payload:     tc.payload,
		}
		err = obj.WithSign(signers, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(len(tc.ks), len(obj.Signatures()))
		for i := range tc.ks {
			assert.Equal(tc.toSigns[i], obj.mm.Signatures[i].toSign, tc.title)
		}

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		assert.NotEqual(tc.output, output, tc.title)

		var obj2 SignMessage[[]byte]
		require.NoError(t, key.UnmarshalCBOR(output, &obj2), tc.title)
		require.NoError(t, obj2.Verify(verifiers, tc.external), tc.title)
		assert.Equal(len(tc.ks), len(obj2.Signatures()))
		for i := range tc.ks {
			assert.Equal(tc.toSigns[i], obj2.mm.Signatures[i].toSign, tc.title)
			assert.Equal(obj.Signatures()[i].Signature(), obj2.Signatures()[i].Signature(), tc.title)
		}
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.payload, obj2.Payload, tc.title)

		var obj3 SignMessage[[]byte]
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj3), tc.title)
		require.NoError(t, obj3.Verify(verifiers, tc.external), tc.title)
		assert.Equal(len(tc.ks), len(obj3.Signatures()))
		for i := range tc.ks {
			assert.Equal(tc.toSigns[i], obj3.mm.Signatures[i].toSign, tc.title)
			assert.NotEqual(obj.Signatures()[i].Signature(), obj3.Signatures()[i].Signature(), tc.title)
		}
		assert.Equal(tc.payload, obj3.Payload, tc.title)
		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj3.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj3.Bytesify(), tc.title)
		}

		obj4, err := VerifySignMessage[[]byte](verifiers, tc.output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(len(tc.ks), len(obj4.Signatures()))
		for i := range tc.ks {
			assert.Equal(tc.toSigns[i], obj4.mm.Signatures[i].toSign, tc.title)
			assert.NotEqual(obj.Signatures()[i].Signature(), obj4.Signatures()[i].Signature(), tc.title)
		}
		assert.Equal(tc.payload, obj4.Payload, tc.title)

		if tc.removeTag {
			assert.Equal(tc.output, RemoveCBORTag(obj4.Bytesify()), tc.title)
		} else {
			assert.Equal(tc.output, obj4.Bytesify(), tc.title)
		}

		output, err = obj4.SignAndEncode(signers, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(len(tc.ks), len(obj4.Signatures()))
		for i := range tc.ks {
			assert.Equal(tc.toSigns[i], obj4.mm.Signatures[i].toSign, tc.title)
			assert.NotEqual(obj.Signatures()[i].Signature(), obj4.Signatures()[i].Signature(), tc.title)
		}

		obj4, err = VerifySignMessage[[]byte](verifiers, output, tc.external)
		require.NoError(t, err, tc.title)
		assert.Equal(len(tc.ks), len(obj4.Signatures()))
		for i := range tc.ks {
			assert.Equal(tc.toSigns[i], obj4.mm.Signatures[i].toSign, tc.title)
			assert.NotEqual(obj.Signatures()[i].Signature(), obj4.Signatures()[i].Signature(), tc.title)
		}
		assert.Equal(tc.payload, obj4.Payload, tc.title)
	}
}

func TestSignEdgeCase(t *testing.T) {
	t.Run("common edge case", func(t *testing.T) {
		assert := assert.New(t)

		k, err := ed25519.GenerateKey()
		require.NoError(t, err)
		ks := key.KeySet{k}

		signers, err := ks.Signers()
		require.NoError(t, err)

		verifiers, err := ks.Verifiers()
		require.NoError(t, err)

		var obj *SignMessage[[]byte]
		assert.ErrorContains(obj.UnmarshalCBOR([]byte{0x84}), "nil SignMessage")

		obj = &SignMessage[[]byte]{
			Payload: []byte("This is the content."),
		}
		assert.ErrorContains(obj.Verify(verifiers, nil), "should call SignMessage.UnmarshalCBOR")

		_, err = obj.MarshalCBOR()
		assert.ErrorContains(err, "should call SignMessage.WithSign")
		_, err = key.MarshalCBOR(obj)
		assert.ErrorContains(err, "should call SignMessage.WithSign")

		assert.Nil(obj.Bytesify())
		assert.Nil(obj.Signatures())

		signers[0].Key().SetOps(iana.KeyOperationVerify)
		assert.ErrorContains(obj.WithSign(signers, nil), "invalid key_ops")
		_, err = obj.SignAndEncode(signers, nil)
		assert.ErrorContains(err, "invalid key_ops")
		signers[0].Key().SetOps(iana.KeyOperationSign)
		assert.NoError(obj.WithSign(signers, nil))
		sigs := obj.Signatures()
		assert.Equal(1, len(sigs))

		verifiers[0].Key().SetOps(iana.KeyOperationSign)
		assert.ErrorContains(obj.Verify(verifiers, nil), "invalid key_ops")

		verifiers[0].Key().SetOps(iana.KeyOperationVerify)
		assert.NoError(obj.Verify(verifiers, nil))

		data1, err := obj.MarshalCBOR()
		require.NoError(t, err)
		data2, err := key.MarshalCBOR(obj)
		require.NoError(t, err)
		assert.Equal(data1, data2)

		var obj1 SignMessage[[]byte]
		assert.NoError(key.UnmarshalCBOR(data1, &obj1))
		assert.NoError(obj1.Verify(verifiers, nil))
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(sigs[0].Signature(), obj1.Signatures()[0].Signature())

		_, err = VerifySignMessage[[]byte](verifiers, data2[5:], nil)
		assert.ErrorContains(err, "cbor: cannot unmarshal")
		obj2, err := VerifySignMessage[[]byte](verifiers, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(sigs[0].Signature(), obj2.Signatures()[0].Signature())

		data2 = append(cwtPrefix, data2...)
		obj2, err = VerifySignMessage[[]byte](verifiers, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(sigs[0].Signature(), obj2.Signatures()[0].Signature())
		assert.NotEqual(data2, obj2.Bytesify())

		data2 = RemoveCBORTag(data2)
		obj2, err = VerifySignMessage[[]byte](verifiers, data2, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj2.Payload)
		assert.Equal(sigs[0].Signature(), obj2.Signatures()[0].Signature())
		assert.NotEqual(data2, obj2.Bytesify())
	})

	t.Run("payload cbor.RawMessage", func(t *testing.T) {
		assert := assert.New(t)

		k, err := ecdsa.GenerateKey(iana.AlgorithmES256)
		require.NoError(t, err)
		ks := key.KeySet{k}

		signers, err := ks.Signers()
		require.NoError(t, err)

		verifiers, err := ks.Verifiers()
		require.NoError(t, err)

		obj := &SignMessage[cbor.RawMessage]{
			Protected:   Headers{},
			Unprotected: Headers{},
			Payload:     key.MustMarshalCBOR("This is the content."),
		}

		data, err := obj.SignAndEncode(signers, nil)
		require.NoError(t, err)
		sigs := obj.Signatures()
		assert.Equal(1, len(sigs))

		k1, err := ecdsa.GenerateKey(iana.AlgorithmES384)
		require.NoError(t, err)
		ks1 := key.KeySet{k1}
		verifiers1, err := ks1.Verifiers()
		require.NoError(t, err)
		_, err = VerifySignMessage[cbor.RawMessage](verifiers1, data, nil)
		assert.ErrorContains(err,
			`no verifier for kid`)

		verifiers1[0].Key().SetKid(k.Kid())
		_, err = VerifySignMessage[cbor.RawMessage](verifiers1, data, nil)
		assert.ErrorContains(err,
			`verifier'alg mismatch, expected -7, got -35`)

		obj1, err := VerifySignMessage[cbor.RawMessage](verifiers, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload, obj1.Payload)
		assert.Equal(sigs[0].Signature(), obj1.Signatures()[0].Signature())
		assert.Equal(data, obj1.Bytesify())
	})

	t.Run("payload T", func(t *testing.T) {
		assert := assert.New(t)

		k, err := ed25519.GenerateKey()
		require.NoError(t, err)
		ks := key.KeySet{k}

		signers, err := ks.Signers()
		require.NoError(t, err)

		verifiers, err := ks.Verifiers()
		require.NoError(t, err)

		type T struct {
			Str string
		}

		obj := &SignMessage[T]{
			Payload: T{"This is the content."},
		}

		data, err := obj.SignAndEncode(signers, nil)
		require.NoError(t, err)
		sigs := obj.Signatures()
		assert.Equal(1, len(sigs))

		obj1, err := VerifySignMessage[T](verifiers, data, nil)
		require.NoError(t, err)
		assert.Equal(obj.Payload.Str, obj1.Payload.Str)
		assert.Equal(sigs[0].Signature(), obj1.Signatures()[0].Signature())
		assert.Equal(data, obj1.Bytesify())
	})
}
