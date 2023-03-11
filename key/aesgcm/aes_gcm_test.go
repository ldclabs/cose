// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesgcm

import (
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCM(t *testing.T) {
	assert := assert.New(t)

	for _, alg := range []int{
		iana.AlgorithmA128GCM,
		iana.AlgorithmA192GCM,
		iana.AlgorithmA256GCM,
	} {
		k, err := GenerateKey(alg)
		require.NoError(t, err)
		assert.Equal(alg, int(k.Alg()))
		assert.NoError(CheckKey(k))

		encryptor, err := New(k)
		require.NoError(t, err)
		assert.Equal(k.Kid(), encryptor.Key().Kid())

		iv := key.GetRandomBytes(uint16(encryptor.NonceSize()))

		ciphertext, err := encryptor.Encrypt(iv, []byte("hello world"), []byte("aad"))
		require.NoError(t, err)

		plaintext, err := encryptor.Decrypt(iv, ciphertext, []byte("aad"))
		require.NoError(t, err)
		assert.Equal([]byte("hello world"), plaintext)
		_, err = encryptor.Decrypt(iv, ciphertext, []byte("aae"))
		assert.ErrorContains(err, "message authentication failed")
	}
}

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey(iana.AlgorithmEdDSA)
	assert.ErrorContains(err, "algorithm mismatch -8")
	assert.Nil(k)

	k, err = GenerateKey(0)
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmA128GCM, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))
}

func TestKeyFrom(t *testing.T) {
	assert := assert.New(t)

	k, err := KeyFrom(iana.AlgorithmReserved, []byte{1, 2, 3})
	assert.ErrorContains(err, "algorithm mismatch 0")
	assert.Nil(k)

	k, err = KeyFrom(iana.AlgorithmA128GCM, []byte{1, 2, 3})
	assert.ErrorContains(err, "invalid key size, expected 16, got 3")
	assert.Nil(k)

	data := key.GetRandomBytes(16)
	k, err = KeyFrom(iana.AlgorithmA128GCM, data)
	require.NoError(t, err)

	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmA128GCM, int(k.Alg()))
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
		iana.KeyParameterBaseIV:   []byte{1, 2, 3, 4},
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
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid key size, expected 16, got 4`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
		iana.KeyParameterKid:        "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
		iana.KeyParameterKid:        []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
	}
	assert.NoError(CheckKey(k))
}

func TestEncryptor(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	encryptor, err := New(k)
	assert.ErrorContains(err, `invalid key size, expected 16, got 4`)
	assert.Nil(encryptor)

	k[iana.SymmetricKeyParameterK] = key.GetRandomBytes(16)
	encryptor, err = New(k)
	require.NoError(t, err)

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
}

func TestEncryptorExamples(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/aes-gcm-examples
	for i, tc := range []struct {
		key        key.Key
		plaintext  []byte
		iv         []byte
		aad        []byte
		ciphertext []byte
	}{
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			[]byte("This is the content."),
			key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
			key.HexBytesify("8367456E637279707443A1010140"),
			key.HexBytesify("60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC"),
		},
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmA192GCM,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A7988"),
			},
			[]byte("This is the content."),
			key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
			key.HexBytesify("8367456E637279707443A1010240"),
			key.HexBytesify("134D3B9223A00C1552C77585C157F467F295919D12124F19F521484C0725410947B4D1CA"),
		},
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmA256GCM,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
			},
			[]byte("This is the content."),
			key.HexBytesify("02D1F7E6F26C43D4868D87CE"),
			key.HexBytesify("8367456E637279707443A1010340"),
			key.HexBytesify("9D64A5A59A3B04867DCCF6B8EF82F7D1A3B25EF862B6EDDB29DF2EF16582172E5B5FC757"),
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
