// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecipient(t *testing.T) {
	t.Run("common case", func(t *testing.T) {
		assert := assert.New(t)

		r1 := &Recipient{}
		data, err := r1.MarshalCBOR()
		require.NoError(t, err)
		assert.Nil(r1.Protected)
		assert.Nil(r1.Unprotected)

		r2 := &Recipient{}
		assert.NoError(r2.UnmarshalCBOR(data))
		assert.Equal(r1.Bytesify(), r2.Bytesify())
		assert.Equal(Headers{}, r2.Protected)
		assert.Equal(Headers{}, r2.Unprotected)

		r1 = &Recipient{}
		data, err = key.MarshalCBOR(r1)
		require.NoError(t, err)
		assert.Nil(r1.Protected)
		assert.Nil(r1.Unprotected)

		r2 = &Recipient{}
		assert.NoError(key.UnmarshalCBOR(data, r2))
		assert.Equal(r1.Bytesify(), r2.Bytesify())
		assert.Equal(Headers{}, r2.Protected)
		assert.Equal(Headers{}, r2.Unprotected)

		r1 = &Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect,
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{},
		}
		data, err = key.MarshalCBOR(r1)
		require.NoError(t, err)

		r2 = &Recipient{}
		assert.NoError(key.UnmarshalCBOR(data, r2))
		assert.Equal(r1.Bytesify(), r2.Bytesify())

		r2 = &Recipient{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmECDH_SS_HKDF_256,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: nil,
		}
		data = r2.Bytesify()
		assert.NotEqual(r1.Bytesify(), data)
		assert.Equal(byte(0xf6), data[len(data)-1])

		assert.Nil(r1.Recipients())
		assert.ErrorContains(r1.AddRecipient(nil), "nil Recipient")
		assert.ErrorContains(r1.AddRecipient(r1), "should not add itself")
		assert.NoError(r1.AddRecipient(r2))
		assert.Equal("Rec_Recipient", r2.context)
		assert.Same(r2, r1.Recipients()[0])
		assert.ErrorContains(r1.AddRecipient(r2), `should not have "Rec_Recipient" context`)
		assert.ErrorContains(r2.AddRecipient(r1), `should not have nested recipients`)

		var r3 Recipient
		assert.NoError(key.UnmarshalCBOR(key.MustMarshalCBOR(r1), &r3))
		assert.Equal(r1.Bytesify(), r3.Bytesify())
		assert.Equal(r2.Bytesify(), r3.Recipients()[0].Bytesify())

		r2 = &Recipient{
			Protected: Headers{
				iana.HeaderParameterAlg: func() {},
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: nil,
		}
		_, err = r2.MarshalCBOR()
		assert.ErrorContains(err, "cbor: unsupported type")
	})

	t.Run("Recipient.UnmarshalCBOR", func(t *testing.T) {
		assert := assert.New(t)

		var r4 *Recipient
		assert.ErrorContains(r4.UnmarshalCBOR([]byte{}), "nil Recipient")

		r4 = &Recipient{}
		assert.ErrorContains(r4.UnmarshalCBOR([]byte{}), "empty data")
		assert.ErrorContains(r4.UnmarshalCBOR([]byte{0x85}), "invalid data")

		r := &Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{1, 2, 3, 4},
		}
		data := key.MustMarshalCBOR(r)
		assert.NoError(r4.UnmarshalCBOR(data))
		assert.Equal(r.Ciphertext, r4.Ciphertext)
		assert.Equal(r.Bytesify(), r4.Bytesify())

		r4 = &Recipient{}
		r = &Recipient{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmECDH_SS_HKDF_256,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{1, 2, 3, 4},
		}
		data = key.MustMarshalCBOR(r)
		datae := make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[3])
		datae[3] = 0x60
		assert.ErrorContains(r4.UnmarshalCBOR(datae), "cbor: ")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[7])
		datae[7] = 0x60
		assert.ErrorContains(r4.UnmarshalCBOR(datae), "cbor: ")
		assert.NoError(r4.UnmarshalCBOR(data))
		assert.Equal(r.Ciphertext, r4.Ciphertext)
		assert.Equal(r.Bytesify(), r4.Bytesify())

		r4 = &Recipient{}
		data = key.MustMarshalCBOR(r)
		data[0] = 0x84
		data = append(data, 0xf6)
		assert.ErrorContains(r4.UnmarshalCBOR(data), "no recipients")

		data[len(data)-1] = 0x80
		assert.ErrorContains(r4.UnmarshalCBOR(data), "no recipients")

		data[len(data)-1] = 0x81
		data = append(data, 0xf6)
		assert.ErrorContains(r4.UnmarshalCBOR(data), "nil Recipient")

		data = key.MustMarshalCBOR(r)
		data[0] = 0x84
		data = append(data, 0x81)
		data = append(data, r.Bytesify()...)
		assert.NoError(r4.UnmarshalCBOR(data))
		assert.Equal(r.Ciphertext, r4.Ciphertext)
		assert.Equal(r.Ciphertext, r4.Recipients()[0].Ciphertext)
		assert.Equal(r.Bytesify(), r4.Recipients()[0].Bytesify())

		data = key.MustMarshalCBOR(r)
		data[0] = 0x84
		data = append(data, 0x81)
		data = append(data, r4.Bytesify()...)

		r4 = &Recipient{}
		assert.ErrorContains(r4.UnmarshalCBOR(data), "should not have nested recipients")

		r = &Recipient{
			Protected: Headers{
				iana.HeaderParameterAlg: iana.AlgorithmECDH_SS_HKDF_256,
			},
			Unprotected: Headers{
				iana.HeaderParameterKid: []byte("our-secret"),
			},
			Ciphertext: []byte{1, 2, 3, 4},
		}
		r.AddRecipient(&Recipient{
			Protected: Headers{},
			Unprotected: Headers{
				iana.HeaderParameterKid: []byte("our-secret"),
			},
		})
		data = key.MustMarshalCBOR(r)
		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x01), datae[3])
		datae[3] = 0x60
		assert.ErrorContains(r4.UnmarshalCBOR(datae), "cbor: ")

		datae = make([]byte, len(data))
		copy(datae, data)
		assert.Equal(byte(0x04), datae[7])
		datae[7] = 0x60
		assert.ErrorContains(r4.UnmarshalCBOR(datae), "cbor: ")
		assert.NoError(r4.UnmarshalCBOR(data))
		assert.Equal(r.Ciphertext, r4.Ciphertext)
		assert.Equal(r.Bytesify(), r4.Bytesify())
	})
}
