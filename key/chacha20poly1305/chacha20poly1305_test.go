// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chacha20poly1305

import (
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey()
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmChaCha20Poly1305, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))
}

func TestKeyFrom(t *testing.T) {
	assert := assert.New(t)

	k, err := KeyFrom([]byte{1, 2, 3})
	assert.ErrorContains(err, "invalid key size, expected 32, got 3")
	assert.Nil(k)

	data := key.GetRandomBytes(32)
	k, err = KeyFrom(data)
	require.NoError(t, err)

	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmChaCha20Poly1305, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))

	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	require.NoError(t, err)
	assert.Equal(data, kb)
	data[0] += 1
	assert.NotEqual(data, kb)
}

func TestCheckKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	assert.ErrorContains(CheckKey(k), `invalid key type, expected "Symmetric":4, got 0`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeSymmetric,
		iana.KeyParameterAlg: iana.AlgorithmEdDSA,
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch -8`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeSymmetric,
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationEncrypt, iana.KeyOperationSign},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops 1`)

	k = key.Key{
		iana.KeyParameterKty:      iana.KeyTypeSymmetric,
		iana.KeyParameterReserved: true,
	}
	assert.ErrorContains(CheckKey(k), `redundant parameter 0`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.SymmetricKeyParameterK: "hello world",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter k`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 0`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid key size, expected 32, got 4`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(32),
		iana.KeyParameterKid:        "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(32),
		iana.KeyParameterKid:        []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))
}

func TestEncryptor(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	encryptor, err := New(k)
	assert.ErrorContains(err, `invalid key size, expected 32, got 4`)
	assert.Nil(encryptor)

	k[iana.SymmetricKeyParameterK] = key.GetRandomBytes(32)
	encryptor, err = New(k)
	require.NoError(t, err)
	assert.Equal(iana.AlgorithmChaCha20Poly1305, int(encryptor.Key().Alg()))

	iv := key.GetRandomBytes(uint16(encryptor.NonceSize()))

	ciphertext, err := encryptor.Encrypt(iv, []byte("hello world"), nil)
	require.NoError(t, err)

	plaintext, err := encryptor.Decrypt(iv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal([]byte("hello world"), plaintext)

	_, err = encryptor.Decrypt(iv, ciphertext, []byte("aad"))
	assert.ErrorContains(err, "message authentication failed")

	ciphertext, err = encryptor.Encrypt(iv, []byte("hello world"), []byte("aad"))
	require.NoError(t, err)
	plaintext, err = encryptor.Decrypt(iv, ciphertext, []byte("aad"))
	require.NoError(t, err)
	assert.Equal([]byte("hello world"), plaintext)

	iv[0] += 1
	_, err = encryptor.Decrypt(iv, ciphertext, []byte("aad"))
	assert.ErrorContains(err, "message authentication failed")

	k.SetOps(iana.KeyOperationDecrypt)
	_, err = encryptor.Encrypt(iv, []byte("hello world"), nil)
	assert.ErrorContains(err, "invalid key_ops")

	k.SetOps(iana.KeyOperationEncrypt)
	_, err = encryptor.Encrypt(iv[1:], []byte("hello world"), nil)
	assert.ErrorContains(err, "invalid nonce size, expected 12, got 11")

	ciphertext, err = encryptor.Encrypt(iv, []byte("hello world"), nil)
	require.NoError(t, err)
	_, err = encryptor.Decrypt(iv, ciphertext, nil)
	assert.ErrorContains(err, "invalid key_ops")

	k.SetOps(iana.KeyOperationDecrypt)
	_, err = encryptor.Decrypt(iv[1:], ciphertext, nil)
	assert.ErrorContains(err, "invalid nonce size, expected 12, got 11")

	plaintext, err = encryptor.Decrypt(iv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal([]byte("hello world"), plaintext)

	k.SetOps()
	k[iana.SymmetricKeyParameterK] = []byte{1, 2, 3, 4}
	_, err = encryptor.Encrypt(iv, []byte("hello world"), nil)
	assert.ErrorContains(err, "chacha20poly1305: bad key length")

	_, err = encryptor.Decrypt(iv, ciphertext, nil)
	assert.ErrorContains(err, "chacha20poly1305: bad key length")
}

func TestEncryptorExamples(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/chacha-poly-examples
	// https://github.com/cose-wg/Examples/pull/104
	for i, tc := range []struct {
		key        key.Key
		plaintext  []byte
		iv         []byte
		aad        []byte
		ciphertext []byte
	}{
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
			},
			[]byte("This is the content."),
			key.HexBytesify("26682306D4FB28CA01B43B80"),
			key.HexBytesify("8367456E637279707444A101181840"),
			key.HexBytesify("1CD5D49DAA014CCAFFB30E765DC5CD410689AAE1C60B45648853298FF6808DB3FA8235DB"),
		},
	} {
		testmsg := fmt.Sprintf("test case %d", i)

		encryptor, err := New(tc.key)
		require.NoError(t, err, testmsg)

		ciphertext, err := encryptor.Encrypt(tc.iv, tc.plaintext, tc.aad)
		require.NoError(t, err)

		assert.Equal(tc.ciphertext, ciphertext, testmsg)
	}
}
