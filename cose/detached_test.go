// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesgcm"
	_ "github.com/ldclabs/cose/key/aesmac"
	"github.com/ldclabs/cose/key/ed25519"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func symKey(alg int) key.Key {
	return key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("detached-secret"),
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
	}
}

func TestSign1Detached(t *testing.T) {
	assert := assert.New(t)

	priv, err := ed25519.GenerateKey()
	require.NoError(t, err)
	signer, err := priv.Signer()
	require.NoError(t, err)
	pub, err := ed25519.ToPublicKey(priv)
	require.NoError(t, err)
	verifier, err := pub.Verifier()
	require.NoError(t, err)

	payload := []byte("detached content")

	// detached encoding differs from attached and the wire payload is nil (0xf6).
	attached, err := (&Sign1Message[[]byte]{Payload: payload}).SignAndEncode(signer, nil)
	require.NoError(t, err)
	detached, err := (&Sign1Message[[]byte]{Payload: payload}).SignDetachedAndEncode(signer, nil)
	require.NoError(t, err)
	assert.NotEqual(attached, detached)
	assert.Less(len(detached), len(attached))

	// the externally supplied payload verifies.
	verified, err := VerifySign1MessageDetached[[]byte](verifier, detached, payload, nil)
	require.NoError(t, err)
	assert.Equal(payload, verified.Payload)
	// re-encoding a detached message stays detached.
	assert.Equal(detached, verified.Bytesify())

	// a wrong payload fails.
	_, err = VerifySign1MessageDetached[[]byte](verifier, detached, []byte("wrong"), nil)
	assert.Error(err)

	// attached verification of a detached message fails (signed payload != nil).
	_, err = VerifySign1Message[[]byte](verifier, detached, nil)
	assert.Error(err)
}

func TestSignDetached(t *testing.T) {
	assert := assert.New(t)

	priv, err := ed25519.GenerateKey()
	require.NoError(t, err)
	signer, err := priv.Signer()
	require.NoError(t, err)
	pub, err := ed25519.ToPublicKey(priv)
	require.NoError(t, err)
	verifier, err := pub.Verifier()
	require.NoError(t, err)

	payload := []byte("detached content")
	detached, err := (&SignMessage[[]byte]{Payload: payload}).
		SignDetachedAndEncode(key.Signers{signer}, nil)
	require.NoError(t, err)

	verified, err := VerifySignMessageDetached[[]byte](
		key.Verifiers{verifier}, detached, payload, nil)
	require.NoError(t, err)
	assert.Equal(payload, verified.Payload)
	assert.Equal(detached, verified.Bytesify())

	_, err = VerifySignMessageDetached[[]byte](key.Verifiers{verifier}, detached, []byte("wrong"), nil)
	assert.Error(err)
}

func TestMac0Detached(t *testing.T) {
	assert := assert.New(t)

	macer, err := symKey(iana.AlgorithmAES_MAC_256_64).MACer()
	require.NoError(t, err)

	payload := []byte("detached content")
	detached, err := (&Mac0Message[[]byte]{Payload: payload}).ComputeDetachedAndEncode(macer, nil)
	require.NoError(t, err)

	verified, err := VerifyMac0MessageDetached[[]byte](macer, detached, payload, nil)
	require.NoError(t, err)
	assert.Equal(payload, verified.Payload)
	assert.Equal(detached, verified.Bytesify())

	_, err = VerifyMac0MessageDetached[[]byte](macer, detached, []byte("wrong"), nil)
	assert.Error(err)

	_, err = VerifyMac0Message[[]byte](macer, detached, nil)
	assert.Error(err)
}

func TestMacDetached(t *testing.T) {
	assert := assert.New(t)

	macer, err := symKey(iana.AlgorithmAES_MAC_256_64).MACer()
	require.NoError(t, err)

	payload := []byte("detached content")
	obj := &MacMessage[[]byte]{Payload: payload}
	require.NoError(t, obj.ComputeDetached(macer, nil))
	require.NoError(t, obj.AddRecipient(&Recipient{
		Unprotected: Headers{iana.HeaderParameterAlg: iana.AlgorithmDirect},
		Ciphertext:  []byte{},
	}))
	detached, err := obj.MarshalCBOR()
	require.NoError(t, err)

	verified, err := VerifyMacMessageDetached[[]byte](macer, detached, payload, nil)
	require.NoError(t, err)
	assert.Equal(payload, verified.Payload)

	_, err = VerifyMacMessageDetached[[]byte](macer, detached, []byte("wrong"), nil)
	assert.Error(err)
}

func TestEncrypt0Detached(t *testing.T) {
	assert := assert.New(t)

	encryptor, err := symKey(iana.AlgorithmA256GCM).Encryptor()
	require.NoError(t, err)

	payload := []byte("detached content")
	obj := &Encrypt0Message[[]byte]{Payload: payload}
	ciphertext, err := obj.EncryptDetached(encryptor, nil)
	require.NoError(t, err)
	assert.NotEmpty(ciphertext)

	detached, err := obj.MarshalCBOR()
	require.NoError(t, err)
	// the wire ciphertext is nil (0xf6).
	assert.Equal(byte(0xf6), detached[len(detached)-1])

	decrypted, err := DecryptEncrypt0MessageDetached[[]byte](encryptor, detached, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(payload, decrypted.Payload)

	// a corrupted detached ciphertext fails authentication.
	bad := make([]byte, len(ciphertext))
	copy(bad, ciphertext)
	bad[0] ^= 0xff
	_, err = DecryptEncrypt0MessageDetached[[]byte](encryptor, detached, bad, nil)
	assert.Error(err)

	// empty ciphertext is rejected.
	_, err = DecryptEncrypt0MessageDetached[[]byte](encryptor, detached, nil, nil)
	assert.ErrorContains(err, "empty ciphertext")
}

func TestEncryptDetached(t *testing.T) {
	assert := assert.New(t)

	encryptor, err := symKey(iana.AlgorithmA256GCM).Encryptor()
	require.NoError(t, err)

	payload := []byte("detached content")
	obj := &EncryptMessage[[]byte]{Payload: payload}
	ciphertext, err := obj.EncryptDetached(encryptor, nil)
	require.NoError(t, err)
	require.NoError(t, obj.AddRecipient(&Recipient{
		Unprotected: Headers{iana.HeaderParameterAlg: iana.AlgorithmDirect},
		Ciphertext:  []byte{},
	}))

	detached, err := obj.MarshalCBOR()
	require.NoError(t, err)

	decrypted, err := DecryptEncryptMessageDetached[[]byte](encryptor, detached, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(payload, decrypted.Payload)

	bad := make([]byte, len(ciphertext))
	copy(bad, ciphertext)
	bad[0] ^= 0xff
	_, err = DecryptEncryptMessageDetached[[]byte](encryptor, detached, bad, nil)
	assert.Error(err)
}
