// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesgcm"
	"github.com/ldclabs/cose/key/ed25519"
)

func TestProtectedHeadersFromEmptyMapBytes(t *testing.T) {
	assert := assert.New(t)

	h, protected, err := protectedHeadersFromBytes([]byte{0xa0})
	assert.NoError(err)
	assert.Equal(Headers{}, h)
	assert.Equal([]byte{}, protected)
}

func TestSign1VerifyAcceptsEmptyProtectedMapEncoding(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	priv, err := ed25519.GenerateKey()
	require.NoError(err)
	signer, err := priv.Signer()
	require.NoError(err)
	pub, err := ed25519.ToPublicKey(priv)
	require.NoError(err)
	verifier, err := pub.Verifier()
	require.NoError(err)

	payload := []byte("payload")
	toSign := key.MustMarshalCBOR([]any{"Signature1", []byte{}, []byte{}, payload})
	sig, err := signer.Sign(toSign)
	require.NoError(err)

	raw := key.MustMarshalCBOR([]any{
		[]byte{0xa0}, // protected bucket encoded as a zero-length map.
		map[any]any{},
		payload,
		sig,
	})

	var m Sign1Message[[]byte]
	require.NoError(m.UnmarshalCBOR(raw))
	assert.NoError(m.Verify(verifier, nil))
}

func TestSignVerifyUsesEncodedSignerProtectedBytes(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	priv, err := ed25519.GenerateKey()
	require.NoError(err)
	signer, err := priv.Signer()
	require.NoError(err)
	pub, err := ed25519.ToPublicKey(priv)
	require.NoError(err)
	verifier, err := pub.Verifier()
	require.NoError(err)

	payload := []byte("payload")
	// Valid protected map {2: [1], 1: -8}, intentionally encoded in a
	// non-canonical key order. Sig_structure must use these exact bytes.
	signProtected := []byte{0xa2, 0x02, 0x81, 0x01, 0x01, 0x27}
	toSign := key.MustMarshalCBOR([]any{"Signature", []byte{}, signProtected, []byte{}, payload})
	sig, err := signer.Sign(toSign)
	require.NoError(err)

	raw := key.MustMarshalCBOR([]any{
		[]byte{},
		map[any]any{},
		payload,
		[]any{
			[]any{signProtected, map[any]any{iana.HeaderParameterKid: pub.Kid()}, sig},
		},
	})

	var m SignMessage[[]byte]
	require.NoError(m.UnmarshalCBOR(raw))
	assert.NoError(m.Verify(key.Verifiers{verifier}, nil))
}

func TestEncrypt0UsesProtectedIV(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	encryptor, err := symKey(iana.AlgorithmA256GCM).Encryptor()
	require.NoError(err)

	iv := []byte("123456789012")
	msg := &Encrypt0Message[[]byte]{
		Protected: Headers{
			iana.HeaderParameterAlg: iana.AlgorithmA256GCM,
			iana.HeaderParameterIV:  iv,
		},
		Unprotected: Headers{},
		Payload:     []byte("payload"),
	}
	coseData, err := msg.EncryptAndEncode(encryptor, nil)
	require.NoError(err)
	assert.False(msg.Unprotected.Has(iana.HeaderParameterIV))

	var raw encrypt0Message
	require.NoError(key.UnmarshalCBOR(coseData[1:], &raw)) // strip COSE_Encrypt0 tag byte
	assert.Equal(map[any]any{}, map[any]any(raw.Unprotected))

	decoded, err := DecryptEncrypt0Message[[]byte](encryptor, coseData, nil)
	require.NoError(err)
	assert.Equal([]byte("payload"), decoded.Payload)
}

func TestCheckHeadersRejectsIVAndPartialIVAcrossBuckets(t *testing.T) {
	assert := assert.New(t)

	err := checkHeaders(
		Headers{iana.HeaderParameterIV: []byte("123456789012")},
		Headers{iana.HeaderParameterPartialIV: []byte{1}},
	)
	assert.ErrorContains(err, "both iv and partial iv")

	raw := key.MustMarshalCBOR([]any{
		key.MustMarshalCBOR(Headers{iana.HeaderParameterIV: []byte("123456789012")}),
		map[any]any{iana.HeaderParameterPartialIV: []byte{1}},
		[]byte("ciphertext"),
	})
	var m Encrypt0Message[[]byte]
	assert.ErrorContains(m.UnmarshalCBOR(raw), "both iv and partial iv")
}

func TestProtectedHeaderBytesTypeError(t *testing.T) {
	assert := assert.New(t)

	_, _, err := headerBytes(Headers{iana.HeaderParameterIV: 1}, nil, iana.HeaderParameterIV)
	assert.Error(err)
}
