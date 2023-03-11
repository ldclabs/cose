// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"

	"github.com/stretchr/testify/assert"
)

func TestHeaders(t *testing.T) {
	assert := assert.New(t)

	h := Headers{}
	assert.False(h.Has(iana.HeaderParameterReserved))

	h = Headers{iana.HeaderParameterReserved: true}
	assert.True(h.Has(iana.HeaderParameterReserved))

	vbool, err := h.GetBool(iana.HeaderParameterReserved)
	assert.NoError(err)
	assert.Equal(true, vbool)

	h = Headers{iana.HeaderParameterReserved: 1}
	vint, err := h.GetInt(iana.HeaderParameterReserved)
	assert.NoError(err)
	assert.Equal(1, vint)

	h = Headers{iana.HeaderParameterReserved: 1}
	vint64, err := h.GetInt64(iana.HeaderParameterReserved)
	assert.NoError(err)
	assert.Equal(int64(1), vint64)

	h = Headers{iana.HeaderParameterReserved: 1}
	vuint64, err := h.GetUint64(iana.HeaderParameterReserved)
	assert.NoError(err)
	assert.Equal(uint64(1), vuint64)

	h = Headers{iana.HeaderParameterReserved: []byte{1, 2, 3, 4}}
	vbytes, err := h.GetBytes(iana.HeaderParameterReserved)
	assert.NoError(err)
	assert.Equal([]byte{1, 2, 3, 4}, vbytes)

	h = Headers{iana.HeaderParameterReserved: "hello"}
	vstr, err := h.GetString(iana.HeaderParameterReserved)
	assert.NoError(err)
	assert.Equal("hello", vstr)

	var p *Headers
	assert.ErrorContains(p.UnmarshalCBOR([]byte{0xa0}), "nil IntMap")

	h = Headers{
		iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
		iana.HeaderParameterKid: []byte{1, 2, 3, 4},
	}

	data, err := key.MarshalCBOR(h)
	assert.NoError(err)

	var h2 Headers
	assert.NoError(h2.UnmarshalCBOR(data))
	assert.Equal(data, h2.Bytesify())

	var h3 Headers
	assert.NoError(key.UnmarshalCBOR(data, &h3))
	assert.Equal(data, h3.Bytesify())

	h = Headers{
		iana.HeaderAlgorithmParameterEphemeralKey: key.Key{
			iana.KeyParameterKty:    iana.KeyTypeEC2,
			iana.EC2KeyParameterCrv: iana.EllipticCurveP_521,
			iana.EC2KeyParameterX:   key.HexBytesify("0043B12669ACAC3FD27898FFBA0BCD2E6C366D53BC4DB71F909A759304ACFB5E18CDC7BA0B13FF8C7636271A6924B1AC63C02688075B55EF2D613574E7DC242F79C3"),
			iana.EC2KeyParameterY:   true,
		},
		iana.HeaderParameterKid: []byte("bilbo.baggins@hobbiton.example"),
	}

	data, err = h.MarshalCBOR()
	assert.NoError(err)

	var h4 Headers
	assert.NoError(h4.UnmarshalCBOR(data))
	assert.Equal(data, h4.Bytesify())
	kid, _ := h4.GetBytes(iana.HeaderParameterKid)
	assert.Equal([]byte("bilbo.baggins@hobbiton.example"), kid)
	im, err := h4.GetIntMap(iana.HeaderAlgorithmParameterEphemeralKey)
	assert.NoError(err)
	x, err := im.GetBytes(iana.EC2KeyParameterX)
	assert.NoError(err)
	assert.Equal(key.HexBytesify("0043B12669ACAC3FD27898FFBA0BCD2E6C366D53BC4DB71F909A759304ACFB5E18CDC7BA0B13FF8C7636271A6924B1AC63C02688075B55EF2D613574E7DC242F79C3"), x)
}

func TestHeaderBytes(t *testing.T) {
	assert := assert.New(t)

	var h Headers
	data, err := h.Bytes()
	assert.NoError(err)
	assert.Equal([]byte{}, data)

	h = Headers{}
	data, err = h.Bytes()
	assert.NoError(err)
	assert.Equal([]byte{}, data)

	h = Headers{iana.HeaderParameterReserved: true}
	data, err = h.Bytes()
	assert.NoError(err)
	assert.Equal(data, key.MustMarshalCBOR(h))

	h, err = HeadersFromBytes(nil)
	assert.NoError(err)
	assert.Equal(Headers{}, h)

	h, err = HeadersFromBytes([]byte{})
	assert.NoError(err)
	assert.Equal(Headers{}, h)

	h, err = HeadersFromBytes(data)
	assert.NoError(err)
	assert.NotEqual(Headers{}, h)
	assert.True(h.Has(iana.HeaderParameterReserved))

	data[1] = 0xf5
	_, err = HeadersFromBytes(data)
	assert.ErrorContains(err, "cbor: ")

	h = Headers{iana.HeaderParameterReserved: func() {}}
	_, err = h.Bytes()
	assert.ErrorContains(err, "cbor: ")
}
