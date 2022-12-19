// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/aesgcm"
	"github.com/ldclabs/cose/key/ecdsa"
)

func TestEncryptMessage(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title     string
		keyS      key.Key
		keyR      key.Key
		cek       []byte
		iv        []byte
		plaintext []byte
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
			key.HexBytesify("8367456E637279707443A1010140"),
			key.HexBytesify("D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A20458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6520A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D628022F5F6"),
		},
	} {
		gcmkey, err := aesgcm.KeyFrom(iana.AlgorithmA128GCM, tc.cek)
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
			Protected: Headers{iana.HeaderParameterAlg: -25}, // ECDH-ES + HKDF-256
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
