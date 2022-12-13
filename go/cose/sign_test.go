// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/go/key"
	_ "github.com/ldclabs/cose/go/key/ecdsa"
)

func TestSign(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title     string
		ks        key.KeySet
		toBeSigns [][]byte
		payload   []byte
		output    []byte
	}{
		{
			`Case: JOSE Cookbook Example 4.8 - multiple signatures`,
			key.KeySet{
				map[key.IntKey]any{
					key.ParamKty: key.KtyEC2,
					key.ParamKid: []byte("11"), //  h'3131'
					key.ParamCrv: key.CrvP256,
					key.ParamX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
					key.ParamY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
					key.ParamD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
				},
				map[key.IntKey]any{
					key.ParamKty: key.KtyEC2,
					key.ParamKid: []byte("bilbo.baggins@hobbiton.example"),
					key.ParamCrv: key.CrvP521,
					key.ParamX:   key.Base64Bytesify("cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0"),
					key.ParamY:   key.Base64Bytesify("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
					key.ParamD:   key.Base64Bytesify("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"),
				},
			},
			[][]byte{
				key.HexBytesify("85695369676E61747572654043A101264054546869732069732074686520636F6E74656E742E"),
				key.HexBytesify("85695369676E61747572654044A10138234054546869732069732074686520636F6E74656E742E"),
			},
			[]byte("This is the content."),
			key.HexBytesify("D8628440A054546869732069732074686520636F6E74656E742E828343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A8344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65588400A2D28A7C2BDB1587877420F65ADF7D0B9A06635DD1DE64BB62974C863F0B160DD2163734034E6AC003B01E8705524C5C4CA479A952F0247EE8CB0B4FB7397BA08D009E0C8BF482270CC5771AA143966E5A469A09F613488030C5B07EC6D722E3835ADB5B2D8C44E95FFB13877DD2582866883535DE3BB03D01753F83AB87BB4F7A0297"),
		},
	} {
		signers, err := tc.ks.Signers()
		require.NoError(t, err, tc.title)

		verifiers, err := tc.ks.Verifiers()
		require.NoError(t, err, tc.title)

		obj := &SignMessage{Payload: tc.payload}
		err = obj.WithSign(signers, nil)
		require.NoError(t, err, tc.title)
		assert.Equal(2, len(obj.Signatures()))
		assert.Equal(tc.toBeSigns[0], obj.sm.Signatures[0].toBeSigned, tc.title)
		assert.Equal(tc.toBeSigns[1], obj.sm.Signatures[1].toBeSigned, tc.title)

		output, err := key.MarshalCBOR(obj)
		require.NoError(t, err, tc.title)
		assert.NotEqual(tc.output, output, tc.title)

		var obj2 SignMessage
		require.NoError(t, key.UnmarshalCBOR(output, &obj2), tc.title)
		require.NoError(t, obj2.Verify(verifiers, nil), tc.title)
		assert.Equal(2, len(obj2.Signatures()))
		assert.Equal(tc.toBeSigns[0], obj2.sm.Signatures[0].toBeSigned, tc.title)
		assert.Equal(tc.toBeSigns[1], obj2.sm.Signatures[1].toBeSigned, tc.title)
		assert.Equal(obj.Signatures()[0].Signature(), obj2.Signatures()[0].Signature(), tc.title)
		assert.Equal(obj.Signatures()[1].Signature(), obj2.Signatures()[1].Signature(), tc.title)
		assert.Equal(output, obj2.Bytesify(), tc.title)
		assert.Equal(tc.payload, obj2.Payload, tc.title)

		var obj3 SignMessage
		require.NoError(t, key.UnmarshalCBOR(tc.output, &obj3), tc.title)
		require.NoError(t, obj3.Verify(verifiers, nil), tc.title)
		assert.Equal(2, len(obj3.Signatures()))
		assert.Equal(tc.toBeSigns[0], obj3.sm.Signatures[0].toBeSigned, tc.title)
		assert.Equal(tc.toBeSigns[1], obj3.sm.Signatures[1].toBeSigned, tc.title)
		assert.NotEqual(obj.Signatures()[0].Signature(), obj3.Signatures()[0].Signature(), tc.title)
		assert.NotEqual(obj.Signatures()[1].Signature(), obj3.Signatures()[1].Signature(), tc.title)
		assert.Equal(tc.output, obj3.Bytesify(), tc.title)
		assert.Equal(tc.payload, obj3.Payload, tc.title)
	}
}
