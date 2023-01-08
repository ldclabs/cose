// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKDFContext(t *testing.T) {
	t.Run("KDFContext", func(t *testing.T) {
		assert := assert.New(t)

		var k *KDFContext
		assert.ErrorContains(k.UnmarshalCBOR([]byte{}), "nil KDFContext")

		k = &KDFContext{}
		assert.ErrorContains(k.UnmarshalCBOR([]byte{}), "empty data")
		assert.ErrorContains(k.UnmarshalCBOR([]byte{0x83}), "invalid data")

		k1 := &KDFContext{}
		data, err := k1.MarshalCBOR()
		require.NoError(t, err)
		assert.Nil(k1.SuppPubInfo.Protected)
		assert.Nil(k1.SuppPrivInfo)

		k2 := &KDFContext{}
		assert.NoError(k2.UnmarshalCBOR(data))
		assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k2))
		assert.Equal(Headers{}, k2.SuppPubInfo.Protected)
		assert.Nil(k2.SuppPrivInfo)

		k1 = &KDFContext{}
		data, err = key.MarshalCBOR(k1)
		require.NoError(t, err)
		assert.Nil(k1.SuppPubInfo.Protected)
		assert.Nil(k1.SuppPrivInfo)

		k2 = &KDFContext{}
		assert.NoError(key.UnmarshalCBOR(data, k2))
		assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k2))
		assert.Equal(Headers{}, k2.SuppPubInfo.Protected)
		assert.Nil(k2.SuppPrivInfo)

		k1 = &KDFContext{
			AlgorithmID: iana.AlgorithmECDH_ES_HKDF_256,
			PartyUInfo: PartyInfo{
				Identity: []byte("Alice"),
				Nonce:    []byte{1, 2, 3, 4},
			},
			SuppPubInfo: SuppPubInfo{
				KeyDataLength: 128,
				Protected: Headers{
					iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
				},
			},
		}
		data, err = key.MarshalCBOR(k1)
		require.NoError(t, err)

		k2 = &KDFContext{}
		assert.NoError(key.UnmarshalCBOR(data, k2))
		assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k2))
		assert.Equal(k1.AlgorithmID, k2.AlgorithmID)
		assert.Equal(k1.PartyUInfo.Identity, k2.PartyUInfo.Identity)
		assert.Equal(k1.PartyUInfo.Nonce, k2.PartyUInfo.Nonce)
		assert.Nil(k2.PartyUInfo.Other)
		assert.Nil(k2.PartyVInfo.Identity)
		assert.Nil(k2.PartyVInfo.Nonce)
		assert.Nil(k2.PartyVInfo.Other)
		assert.Equal(k1.SuppPubInfo.KeyDataLength, k2.SuppPubInfo.KeyDataLength)
		assert.Nil(k2.SuppPrivInfo)

		k1 = &KDFContext{
			AlgorithmID: iana.AlgorithmECDH_ES_HKDF_256,
			PartyUInfo: PartyInfo{
				Identity: []byte("Alice"),
				Nonce:    []byte{1, 2, 3, 4},
			},
			SuppPubInfo: SuppPubInfo{
				KeyDataLength: 128,
				Protected: Headers{
					iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
				},
			},
			SuppPrivInfo: []byte{1, 2, 3, 4, 5, 6},
		}
		data, err = key.MarshalCBOR(k1)
		require.NoError(t, err)

		k2 = &KDFContext{}
		assert.NoError(key.UnmarshalCBOR(data, k2))
		assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k2))
		assert.Equal(k1.AlgorithmID, k2.AlgorithmID)
		assert.Equal(k1.PartyUInfo.Identity, k2.PartyUInfo.Identity)
		assert.Equal(k1.PartyUInfo.Nonce, k2.PartyUInfo.Nonce)
		assert.Nil(k2.PartyUInfo.Other)
		assert.Nil(k2.PartyVInfo.Identity)
		assert.Nil(k2.PartyVInfo.Nonce)
		assert.Nil(k2.PartyVInfo.Other)
		assert.Equal(k1.SuppPubInfo.KeyDataLength, k2.SuppPubInfo.KeyDataLength)
		assert.Equal([]byte{1, 2, 3, 4, 5, 6}, k2.SuppPrivInfo)

		data, err = k1.MarshalCBOR()
		require.NoError(t, err)

		k2 = &KDFContext{}
		assert.NoError(k2.UnmarshalCBOR(data))
		assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k2))
		assert.Equal(k1.AlgorithmID, k2.AlgorithmID)
		assert.Equal(k1.PartyUInfo.Identity, k2.PartyUInfo.Identity)
		assert.Equal(k1.PartyUInfo.Nonce, k2.PartyUInfo.Nonce)
		assert.Nil(k2.PartyUInfo.Other)
		assert.Nil(k2.PartyVInfo.Identity)
		assert.Nil(k2.PartyVInfo.Nonce)
		assert.Nil(k2.PartyVInfo.Other)
		assert.Equal(k1.SuppPubInfo.KeyDataLength, k2.SuppPubInfo.KeyDataLength)
		assert.Equal([]byte{1, 2, 3, 4, 5, 6}, k2.SuppPrivInfo)
	})

	t.Run("SuppPubInfo", func(t *testing.T) {
		assert := assert.New(t)

		var s *SuppPubInfo
		assert.ErrorContains(s.UnmarshalCBOR([]byte{}), "nil SuppPubInfo")

		s = &SuppPubInfo{}
		assert.ErrorContains(s.UnmarshalCBOR([]byte{}), "empty data")
		assert.ErrorContains(s.UnmarshalCBOR([]byte{0x84}), "invalid data")

		s1 := &SuppPubInfo{}
		data, err := s1.MarshalCBOR()
		require.NoError(t, err)
		assert.Nil(s1.Protected)
		assert.Nil(s1.Other)

		s2 := &SuppPubInfo{}
		assert.NoError(s2.UnmarshalCBOR(data))
		assert.Equal(key.MustMarshalCBOR(s1), key.MustMarshalCBOR(s2))
		assert.Equal(Headers{}, s2.Protected)
		assert.Nil(s2.Other)

		s1 = &SuppPubInfo{}
		data, err = key.MarshalCBOR(s1)
		require.NoError(t, err)
		assert.Nil(s1.Protected)
		assert.Nil(s1.Other)

		s2 = &SuppPubInfo{}
		assert.NoError(key.UnmarshalCBOR(data, s2))
		assert.Equal(key.MustMarshalCBOR(s1), key.MustMarshalCBOR(s2))
		assert.Equal(Headers{}, s2.Protected)
		assert.Nil(s2.Other)

		s1 = &SuppPubInfo{
			KeyDataLength: 128,
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
			},
		}
		data, err = key.MarshalCBOR(s1)
		require.NoError(t, err)

		s2 = &SuppPubInfo{}
		assert.NoError(key.UnmarshalCBOR(data, s2))
		assert.Equal(key.MustMarshalCBOR(s1), key.MustMarshalCBOR(s2))
		assert.Equal(s1.KeyDataLength, s2.KeyDataLength)
		alg, _ := s2.Protected.GetInt(iana.HeaderParameterAlg)
		assert.Equal(iana.AlgorithmECDH_ES_HKDF_256, alg)
		assert.Nil(s2.Other)

		s1 = &SuppPubInfo{
			KeyDataLength: 128,
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
			},
			Other: []byte{1, 2, 3, 4},
		}
		data, err = key.MarshalCBOR(s1)
		require.NoError(t, err)

		s2 = &SuppPubInfo{}
		assert.NoError(key.UnmarshalCBOR(data, s2))
		assert.Equal(key.MustMarshalCBOR(s1), key.MustMarshalCBOR(s2))
		assert.Equal(s1.KeyDataLength, s2.KeyDataLength)
		alg, _ = s2.Protected.GetInt(iana.HeaderParameterAlg)
		assert.Equal(iana.AlgorithmECDH_ES_HKDF_256, alg)
		assert.Equal([]byte{1, 2, 3, 4}, s2.Other)

		s1 = &SuppPubInfo{
			KeyDataLength: 128,
			Other:         []byte{1, 2, 3, 4},
		}
		data, err = s1.MarshalCBOR()
		require.NoError(t, err)

		s2 = &SuppPubInfo{}
		assert.NoError(s2.UnmarshalCBOR(data))
		assert.Equal(key.MustMarshalCBOR(s1), key.MustMarshalCBOR(s2))
		assert.Equal(s1.KeyDataLength, s2.KeyDataLength)
		assert.Equal(Headers{}, s2.Protected)
		assert.Equal([]byte{1, 2, 3, 4}, s2.Other)
	})
}
