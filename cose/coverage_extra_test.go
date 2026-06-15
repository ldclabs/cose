// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesgcm"
	_ "github.com/ldclabs/cose/key/aesmac"
	"github.com/ldclabs/cose/key/ed25519"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeadersSet(t *testing.T) {
	assert := assert.New(t)

	h := Headers{}
	assert.NoError(h.Set(iana.HeaderParameterAlg, iana.AlgorithmES256))
	v, err := h.GetInt(iana.HeaderParameterAlg)
	assert.NoError(err)
	assert.Equal(iana.AlgorithmES256, v)

	// an invalid (non int/string) label is rejected.
	assert.Error(h.Set(1.5, "x"))
}

func TestMarshalPayloadHelper(t *testing.T) {
	assert := assert.New(t)

	b, err := marshalPayload([]byte{1, 2, 3})
	assert.NoError(err)
	assert.Equal([]byte{1, 2, 3}, b)

	raw := cbor.RawMessage{0x01, 0x02}
	b, err = marshalPayload(raw)
	assert.NoError(err)
	assert.Equal([]byte(raw), b)

	b, err = marshalPayload(42)
	assert.NoError(err)
	assert.Equal(key.MustMarshalCBOR(42), b)

	// an unmarshalable payload returns an error.
	_, err = marshalPayload(make(chan int))
	assert.Error(err)
}

func TestRecipientClassHelper(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(recipientClassDirect, recipientClass(iana.AlgorithmDirect))
	assert.Equal(recipientClassDirect, recipientClass(iana.AlgorithmDirect_HKDF_AES_128))
	assert.Equal(recipientClassKeyWrap, recipientClass(iana.AlgorithmA192KW))
	assert.Equal(recipientClassKeyTransport, recipientClass(iana.AlgorithmRSAES_OAEP_SHA_256))
	assert.Equal(recipientClassDirectKeyAgreement, recipientClass(iana.AlgorithmECDH_SS_HKDF_512))
	assert.Equal(recipientClassKeyAgreementKeyWrap, recipientClass(iana.AlgorithmECDH_SS_A256KW))
	assert.Equal(recipientClassOther, recipientClass(iana.AlgorithmES256))
}

func TestNormalizeCritCases(t *testing.T) {
	assert := assert.New(t)

	_, ok := normalizeCrit([]any{true}) // element is neither int nor string
	assert.False(ok)
	_, ok = normalizeCrit([]any{[]int{1}})
	assert.False(ok)

	labels, ok := normalizeCrit([]any{int64(3), "x"})
	assert.True(ok)
	assert.Equal([]any{3, "x"}, labels)
}

// a private text-string recipient algorithm is accepted (alg present, class other).
func TestRecipientValidateStringAlg(t *testing.T) {
	assert := assert.New(t)
	assert.NoError((&Recipient{
		Protected: Headers{iana.HeaderParameterAlg: "private-alg"},
	}).Validate())
}

// checkHeaders error returns must be reached through every layer's decoder.
func TestCheckHeadersThroughDecoders(t *testing.T) {
	assert := assert.New(t)

	collProt, err := Headers{iana.HeaderParameterAlg: iana.AlgorithmES256}.Bytes()
	require.NoError(t, err)
	collUn := map[any]any{iana.HeaderParameterAlg: iana.AlgorithmES256}
	recOK := key.MustMarshalCBOR([]any{[]byte{}, map[any]any{}, []byte{}})
	sigOK := key.MustMarshalCBOR([]any{[]byte{}, map[any]any{}, []byte{1}})

	var m0 Mac0Message[[]byte]
	assert.ErrorContains(m0.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte("x"), []byte{0}})),
		"both protected and unprotected")

	var mac MacMessage[[]byte]
	assert.ErrorContains(mac.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte("x"), []byte{0}, []cbor.RawMessage{recOK}})),
		"both protected and unprotected")

	var e0 Encrypt0Message[[]byte]
	assert.ErrorContains(e0.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte("x")})),
		"both protected and unprotected")

	var enc EncryptMessage[[]byte]
	assert.ErrorContains(enc.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte("x"), []cbor.RawMessage{recOK}})),
		"both protected and unprotected")

	var sm SignMessage[[]byte]
	assert.ErrorContains(sm.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte("x"), []cbor.RawMessage{sigOK}})),
		"both protected and unprotected")

	var sig Signature
	assert.ErrorContains(sig.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte{1}})),
		"both protected and unprotected")

	var r3 Recipient
	assert.ErrorContains(r3.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte{}})),
		"both protected and unprotected")

	var r4 Recipient
	assert.ErrorContains(r4.UnmarshalCBOR(
		key.MustMarshalCBOR([]any{collProt, collUn, []byte{}, []cbor.RawMessage{recOK}})),
		"both protected and unprotected")
}

// error and guard paths of the detached APIs.
func TestDetachedErrorPaths(t *testing.T) {
	assert := assert.New(t)

	priv, err := ed25519.GenerateKey()
	require.NoError(t, err)
	signer, err := priv.Signer()
	require.NoError(t, err)
	pub, err := ed25519.ToPublicKey(priv)
	require.NoError(t, err)
	verifier, err := pub.Verifier()
	require.NoError(t, err)
	macer, err := symKey(iana.AlgorithmAES_MAC_256_64).MACer()
	require.NoError(t, err)
	encryptor, err := symKey(iana.AlgorithmA256GCM).Encryptor()
	require.NoError(t, err)

	payload := []byte("x")
	bad := []byte{0xff, 0xff}

	// guards: detached verify/decrypt before UnmarshalCBOR.
	assert.ErrorContains((&Sign1Message[[]byte]{}).VerifyDetached(verifier, payload, nil), "should call")
	assert.ErrorContains((&SignMessage[[]byte]{}).VerifyDetached(key.Verifiers{verifier}, payload, nil), "should call")
	assert.ErrorContains((&Mac0Message[[]byte]{}).VerifyDetached(macer, payload, nil), "should call")
	assert.ErrorContains((&MacMessage[[]byte]{}).VerifyDetached(macer, payload, nil), "should call")
	assert.ErrorContains((&Encrypt0Message[[]byte]{}).DecryptDetached(encryptor, payload, nil), "should call")
	assert.ErrorContains((&EncryptMessage[[]byte]{}).DecryptDetached(encryptor, payload, nil), "should call")

	// EncryptMessage detached: empty ciphertext is rejected.
	em := &EncryptMessage[[]byte]{Payload: payload}
	_, err = em.EncryptDetached(encryptor, nil)
	require.NoError(t, err)
	require.NoError(t, em.AddRecipient(&Recipient{
		Unprotected: Headers{iana.HeaderParameterAlg: iana.AlgorithmDirect},
		Ciphertext:  []byte{},
	}))
	det, err := em.MarshalCBOR()
	require.NoError(t, err)
	var em2 EncryptMessage[[]byte]
	require.NoError(t, em2.UnmarshalCBOR(det))
	assert.ErrorContains(em2.DecryptDetached(encryptor, nil, nil), "empty ciphertext")

	// sign/compute/encrypt detached error paths via protected alg mismatch.
	mismatch := Headers{iana.HeaderParameterAlg: iana.AlgorithmES256}

	assert.Error((&Sign1Message[[]byte]{Protected: mismatch, Payload: payload}).SignDetached(signer, nil))
	_, err = (&Sign1Message[[]byte]{Protected: mismatch, Payload: payload}).SignDetachedAndEncode(signer, nil)
	assert.Error(err)

	_, err = (&SignMessage[[]byte]{Payload: payload}).SignDetachedAndEncode(key.Signers{}, nil) // no signers
	assert.Error(err)

	assert.Error((&Mac0Message[[]byte]{Protected: mismatch, Payload: payload}).ComputeDetached(macer, nil))
	_, err = (&Mac0Message[[]byte]{Protected: mismatch, Payload: payload}).ComputeDetachedAndEncode(macer, nil)
	assert.Error(err)

	assert.Error((&MacMessage[[]byte]{Protected: mismatch, Payload: payload}).ComputeDetached(macer, nil))

	_, err = (&Encrypt0Message[[]byte]{Protected: mismatch, Payload: payload}).EncryptDetached(encryptor, nil)
	assert.Error(err)
	_, err = (&EncryptMessage[[]byte]{Protected: mismatch, Payload: payload}).EncryptDetached(encryptor, nil)
	assert.Error(err)

	// package-level helpers propagate UnmarshalCBOR errors.
	_, err = VerifySign1MessageDetached[[]byte](verifier, bad, payload, nil)
	assert.Error(err)
	_, err = VerifySignMessageDetached[[]byte](key.Verifiers{verifier}, bad, payload, nil)
	assert.Error(err)
	_, err = VerifyMac0MessageDetached[[]byte](macer, bad, payload, nil)
	assert.Error(err)
	_, err = VerifyMacMessageDetached[[]byte](macer, bad, payload, nil)
	assert.Error(err)
	_, err = DecryptEncrypt0MessageDetached[[]byte](encryptor, bad, payload, nil)
	assert.Error(err)
	_, err = DecryptEncryptMessageDetached[[]byte](encryptor, bad, payload, nil)
	assert.Error(err)
}
