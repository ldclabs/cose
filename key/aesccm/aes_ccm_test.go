// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesccm

import (
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESCCM(t *testing.T) {
	assert := assert.New(t)

	for _, alg := range []int{
		iana.AlgorithmAES_CCM_16_64_128,
		iana.AlgorithmAES_CCM_16_64_256,
		iana.AlgorithmAES_CCM_64_64_128,
		iana.AlgorithmAES_CCM_64_64_256,
		iana.AlgorithmAES_CCM_16_128_128,
		iana.AlgorithmAES_CCM_16_128_256,
		iana.AlgorithmAES_CCM_64_128_128,
		iana.AlgorithmAES_CCM_64_128_256,
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
		assert.ErrorContains(err, "ccm:")
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
	assert.Equal(iana.AlgorithmAES_CCM_16_64_128, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))
}

func TestKeyFrom(t *testing.T) {
	assert := assert.New(t)

	k, err := KeyFrom(iana.AlgorithmReserved, []byte{1, 2, 3})
	assert.ErrorContains(err, "algorithm mismatch 0")
	assert.Nil(k)

	k, err = KeyFrom(iana.AlgorithmAES_CCM_16_64_128, []byte{1, 2, 3})
	assert.ErrorContains(err, "invalid key size, expected 16, got 3")
	assert.Nil(k)

	data := key.GetRandomBytes(16)
	k, err = KeyFrom(iana.AlgorithmAES_CCM_16_64_128, data)
	require.NoError(t, err)

	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmAES_CCM_16_64_128, int(k.Alg()))
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
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid key size, expected 16, got 4`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
		iana.KeyParameterKid:        "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
		iana.KeyParameterKid:        []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
	}
	assert.NoError(CheckKey(k))
}

func TestEncryptor(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
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
	assert.ErrorContains(err, "ccm:")

	ciphertext, err = encryptor.Encrypt(iv, []byte("hello world"), []byte("aad"))
	require.NoError(t, err)
	plaintext, err = encryptor.Decrypt(iv, ciphertext, []byte("aad"))
	require.NoError(t, err)
	assert.Equal([]byte("hello world"), plaintext)

	iv[0] += 1
	_, err = encryptor.Decrypt(iv, ciphertext, []byte("aad"))
	assert.ErrorContains(err, "ccm:")

	k.SetOps(iana.KeyOperationDecrypt)
	_, err = encryptor.Encrypt(iv, []byte("hello world"), nil)
	assert.ErrorContains(err, "invalid key_ops")

	k.SetOps(iana.KeyOperationEncrypt)
	_, err = encryptor.Encrypt(iv[1:], []byte("hello world"), nil)
	assert.ErrorContains(err, "invalid nonce size, expected 13, got 12")

	ciphertext, err = encryptor.Encrypt(iv, []byte("hello world"), nil)
	require.NoError(t, err)
	_, err = encryptor.Decrypt(iv, ciphertext, nil)
	assert.ErrorContains(err, "invalid key_ops")

	k.SetOps(iana.KeyOperationDecrypt)
	_, err = encryptor.Decrypt(iv[1:], ciphertext, nil)
	assert.ErrorContains(err, "invalid nonce size, expected 13, got 12")

	plaintext, err = encryptor.Decrypt(iv, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal([]byte("hello world"), plaintext)
}

func TestEncryptorExamples(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/aes-ccm-examples
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
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580933B5261A72F"),
			key.HexBytesify("8367456E637279707443A1010A40"),
			key.HexBytesify("6899DA0A132BD2D2B9B10915743EE1F7B92A46802388816C040275EE"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_128_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580933B5261A72F"),
			key.HexBytesify("8367456E637279707444A101181E40"),
			key.HexBytesify("6899DA0A132BD2D2B9B10915743EE1F7B92A46801D3D61B6E7C964520652F9D3C8347E8A"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_64_64_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580"),
			key.HexBytesify("8367456E637279707443A1010C40"),
			key.HexBytesify("191BD858DEC79FC11DA3428BDFA446AC240D591F9F0F25E3A3FA4E6C"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_64_128_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580"),
			key.HexBytesify("8367456E637279707444A101182040"),
			key.HexBytesify("191BD858DEC79FC11DA3428BDFA446AC240D591F59482AEA4157167842D7BF5EDD68EC92"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580933B5261A72F"),
			key.HexBytesify("8367456E637279707443A1010B40"),
			key.HexBytesify("28B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917A8A3EF3313D6D332"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_128_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580933B5261A72F"),
			key.HexBytesify("8367456E637279707444A101181F40"),
			key.HexBytesify("28B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917348CDDC1FD07F3653AD991F9DFB65D50"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_64_64_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580"),
			key.HexBytesify("8367456E637279707443A1010D40"),
			key.HexBytesify("721908D60812806F2660054238E931ADB575771EE26C547EC3DE06C5"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_64_128_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
			},
			[]byte("This is the content."),
			key.HexBytesify("89F52F65A1C580"),
			key.HexBytesify("8367456E637279707444A101182140"),
			key.HexBytesify("721908D60812806F2660054238E931ADB575771EB58752E5F0FB62A828917386A770CE9C"),
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
