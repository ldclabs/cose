// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesccm"
	_ "github.com/ldclabs/cose/key/ecdsa"
	_ "github.com/ldclabs/cose/key/hmac"
)

func TestRFC8392AppendixAKeys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		kid     []byte
		wireAlg int
		kty     int
	}{
		{
			name:    "A.2.1 128-Bit Symmetric Key",
			data:    rfc8392Hex("a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963313238030a"),
			kid:     []byte("Symmetric128"),
			wireAlg: iana.AlgorithmAES_CCM_16_64_128,
			kty:     iana.KeyTypeSymmetric,
		},
		{
			name: "A.2.2 256-Bit Symmetric Key",
			data: rfc8392Hex("a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d795693880104024c53796d6d6574726963323536030a"),
			kid:  []byte("Symmetric256"),
			// RFC 8392 Figure 6's hex encodes alg=10, while Figure 7's
			// diagnostic notation describes alg=4. Keep the wire vector exact.
			wireAlg: iana.AlgorithmAES_CCM_16_64_128,
			kty:     iana.KeyTypeSymmetric,
		},
		{
			name:    "A.2.3 ECDSA P-256 COSE Key",
			data:    rfc8392Hex("a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f2001010202524173796d6d657472696345434453413235360326"),
			kid:     []byte("AsymmetricECDSA256"),
			wireAlg: iana.AlgorithmES256,
			kty:     iana.KeyTypeEC2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var k key.Key
			require.NoError(t, key.UnmarshalCBOR(tc.data, &k))
			assert.Equal(t, tc.kid, []byte(k.Kid()))
			assert.Equal(t, key.Alg(tc.wireAlg), k.Alg())
			assert.Equal(t, tc.kty, k.Kty())

			var canonical key.Key
			require.NoError(t, key.UnmarshalCBOR(k.Bytesify(), &canonical))
			assert.Equal(t, k.Bytesify(), canonical.Bytesify())
		})
	}
}

func TestRFC8392AppendixAMACedCWT(t *testing.T) {
	macer, err := rfc8392Symmetric256Key().MACer()
	require.NoError(t, err)

	t.Run("A.4 Example MACed CWT", func(t *testing.T) {
		data := rfc8392Hex("d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200")

		msg, err := cose.VerifyMac0Message[Claims](macer, data, nil)
		require.NoError(t, err)
		assert.Equal(t, "coap://as.example.com", msg.Payload.Issuer)
		assert.Equal(t, "erikw", msg.Payload.Subject)
		assert.Equal(t, "coap://light.example.com", msg.Payload.Audience)
		assert.Equal(t, uint64(1444064944), msg.Payload.Expiration)
		assert.Equal(t, uint64(1443944944), msg.Payload.NotBefore)
		assert.Equal(t, uint64(1443944944), msg.Payload.IssuedAt)
		assert.Equal(t, rfc8392Hex("0b71"), []byte(msg.Payload.CWTID))
		assert.Equal(t, rfc8392Hex("093101ef6d789200"), msg.Tag())
		assert.Equal(t, data[2:], msg.Bytesify())
	})

	t.Run("A.7 Example MACed CWT with a Floating-Point Value", func(t *testing.T) {
		data := rfc8392Hex("d18443a10104a1044c53796d6d65747269633235364ba106fb41d584367c20000048b8816f34c0542892")

		msg, err := cose.VerifyMac0Message[ClaimsMap](macer, data, nil)
		require.NoError(t, err)
		assert.Equal(t, 1443944944.5, msg.Payload.Get(iana.CWTClaimIat))
		assert.Equal(t, rfc8392Hex("b8816f34c0542892"), msg.Tag())
		assert.Equal(t, data, msg.Bytesify())
	})
}

func TestRFC8392AppendixAEncryptedCWT(t *testing.T) {
	encryptor, err := rfc8392Symmetric128Key().Encryptor()
	require.NoError(t, err)

	t.Run("A.5 Example Encrypted CWT", func(t *testing.T) {
		data := rfc8392Hex("d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ffe8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562f400ee1d0d6c0fdb559c02421fd384fc2ebe22d7071378b0ea7428fff157444d45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b")

		msg, err := cose.DecryptEncrypt0Message[Claims](encryptor, data, nil)
		require.NoError(t, err)
		assert.Equal(t, "coap://as.example.com", msg.Payload.Issuer)
		assert.Equal(t, "erikw", msg.Payload.Subject)
		assert.Equal(t, data, msg.Bytesify())
	})

	t.Run("A.6 Example Nested CWT", func(t *testing.T) {
		data := rfc8392Hex("d08343a1010aa2044c53796d6d6574726963313238054d4a0694c0e69ee6b5956655c7b258b7f6b0914f993de822cc47e5e57a188d7960b528a747446fe12f0e7de05650dec74724366763f167a29c002dfd15b34d8993391cf49bc91127f545dba8703d66f5b7f1ae91237503d371e6333df9708d78c4fb8a8386c8ff09dc49af768b23179deab78d96490a66d5724fb33900c60799d9872fac6da3bdb89043d67c2a05414ce331b5b8f1ed8ff7138f45905db2c4d5bc8045ab372bff142631610a7e0f677b7e9b0bc73adefdcee16d9d5d284c616abeab5d8c291ce0")

		msg, err := cose.DecryptEncrypt0Message[[]byte](encryptor, data, nil)
		require.NoError(t, err)
		assert.Equal(t, rfc8392SignedCWT(), msg.Payload)
		assert.Equal(t, data, msg.Bytesify())

		verifier, err := rfc8392ECDSAKey().Verifier()
		require.NoError(t, err)
		signed, err := cose.VerifySign1Message[Claims](verifier, msg.Payload, nil)
		require.NoError(t, err)
		assert.Equal(t, "coap://as.example.com", signed.Payload.Issuer)
		assert.Equal(t, rfc8392Hex("5427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"), signed.Signature())
	})
}

func TestRFC8392AppendixAClaimsSetRawMessage(t *testing.T) {
	var raw cbor.RawMessage
	data := rfc8392ClaimsSet()
	require.NoError(t, key.UnmarshalCBOR(data, &raw))
	assert.Equal(t, data, []byte(raw))
}

func rfc8392ClaimsSet() []byte {
	return rfc8392Hex("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71")
}

func rfc8392Symmetric128Key() key.Key {
	return key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("Symmetric128"),
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
		iana.SymmetricKeyParameterK: rfc8392Hex("231f4c4d4d3051fdc2ec0a3851d5b383"),
	}
}

func rfc8392Symmetric256Key() key.Key {
	return key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("Symmetric256"),
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: rfc8392Hex("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
	}
}

func rfc8392ECDSAKey() key.Key {
	return key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("AsymmetricECDSA256"),
		iana.KeyParameterAlg:    iana.AlgorithmES256,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   rfc8392Hex("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
		iana.EC2KeyParameterY:   rfc8392Hex("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
		iana.EC2KeyParameterD:   rfc8392Hex("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
	}
}

func rfc8392SignedCWT() []byte {
	return rfc8392Hex("d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30")
}

func rfc8392Hex(s string) []byte {
	return key.HexBytesify(s)
}
