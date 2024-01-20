// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesmac

import (
	"crypto/aes"
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESMAC(t *testing.T) {
	assert := assert.New(t)

	for _, alg := range []int{
		iana.AlgorithmAES_MAC_128_64,
		iana.AlgorithmAES_MAC_256_64,
		iana.AlgorithmAES_MAC_128_128,
		iana.AlgorithmAES_MAC_256_128,
	} {
		k, err := GenerateKey(alg)
		require.NoError(t, err)
		assert.Equal(alg, int(k.Alg()))
		assert.NoError(CheckKey(k))

		macer, err := New(k)
		require.NoError(t, err)
		assert.Equal(k.Kid(), macer.Key().Kid())

		tag, err := macer.MACCreate([]byte("hello world"))
		require.NoError(t, err)
		_, tagSize := getKeySize(k.Alg())
		assert.Equal(tagSize, len(tag))

		assert.NoError(macer.MACVerify([]byte("hello world"), tag))
		assert.ErrorContains(macer.MACVerify([]byte("hello world 1"), tag), "invalid MAC")
	}
}

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey(iana.AlgorithmA128GCM)
	assert.ErrorContains(err, "algorithm mismatch 1")
	assert.Nil(k)

	k, err = GenerateKey(0)
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmAES_MAC_128_64, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))
}

func TestKeyFrom(t *testing.T) {
	assert := assert.New(t)

	k, err := KeyFrom(iana.AlgorithmReserved, []byte{1, 2, 3})
	assert.ErrorContains(err, "algorithm mismatch 0")
	assert.Nil(k)

	k, err = KeyFrom(iana.AlgorithmAES_MAC_128_64, []byte{1, 2, 3})
	assert.ErrorContains(err, "invalid key size, expected 16, got 3")
	assert.Nil(k)

	data := key.GetRandomBytes(16)
	k, err = KeyFrom(iana.AlgorithmAES_MAC_128_64, data)
	require.NoError(t, err)

	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmAES_MAC_128_64, int(k.Alg()))
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
		iana.KeyParameterAlg: iana.AlgorithmA128GCM,
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeSymmetric,
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationMacCreate, iana.KeyOperationSign},
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
		iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid key size, expected 16, got 4`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
		iana.KeyParameterKid:        "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
		iana.KeyParameterKid:        []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(16),
	}
	assert.NoError(CheckKey(k))
}

func TestMACer(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	macer, err := New(k)
	assert.ErrorContains(err, `invalid key size, expected 16, got 4`)
	assert.Nil(macer)

	k[iana.SymmetricKeyParameterK] = key.GetRandomBytes(16)
	macer, err = New(k)
	require.NoError(t, err)

	tag, err := macer.MACCreate([]byte("hello world"))
	require.NoError(t, err)

	assert.NoError(macer.MACVerify([]byte("hello world"), tag))
	assert.ErrorContains(macer.MACVerify([]byte("hello world 1"), tag), "invalid MAC")

	k.SetOps(iana.KeyOperationMacVerify)
	_, err = macer.MACCreate([]byte("hello world"))
	assert.ErrorContains(err, "invalid key_ops")

	k.SetOps(iana.KeyOperationMacCreate)
	assert.ErrorContains(macer.MACVerify([]byte("hello world"), tag), "invalid key_ops")

	k.SetOps(iana.KeyOperationMacVerify, iana.KeyOperationMacCreate)
	tag, err = macer.MACCreate([]byte("hello world 1"))
	require.NoError(t, err)
	assert.NoError(macer.MACVerify([]byte("hello world 1"), tag))

	macer.(*aesMAC).block, _ = aes.NewCipher(key.GetRandomBytes(16))
	assert.ErrorContains(macer.MACVerify([]byte("hello world 1"), tag), "invalid MAC")
}

func TestMACerExamples(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/cbc-mac-examples
	for i, tc := range []struct {
		key  key.Key
		data []byte
		tag  []byte
	}{
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_64,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			key.HexBytesify("84634D414343A1010E4054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("C1CA820E6E247089"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_128_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E"),
			},
			key.HexBytesify("84634D414344A10118194054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("B242D2A935FEB4D66FF8334AC95BF72B"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_256_64,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
			},
			key.HexBytesify("84634D414343A1010F4054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("9E1226BA1F81B848"),
		},
		{
			map[any]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_256_128,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
			},
			key.HexBytesify("84634D414344A101181A4054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("DB9C7598A0751C5FF3366B6205BD2AA9"),
		},
	} {
		testmsg := fmt.Sprintf("test case %d", i)
		macer, err := New(tc.key)
		require.NoError(t, err, testmsg)

		tag, err := macer.MACCreate(tc.data)
		require.NoError(t, err, testmsg)
		assert.NoError(macer.MACVerify(tc.data, tag), testmsg)

		assert.Equal(tc.tag, tag, testmsg)
	}
}
