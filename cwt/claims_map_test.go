// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"

	"github.com/stretchr/testify/assert"
)

func TestClaimsMap(t *testing.T) {
	assert := assert.New(t)

	cm := ClaimsMap{}
	assert.False(cm.Has(iana.CWTClaimReserved))

	cm = ClaimsMap{iana.CWTClaimReserved: true}
	assert.True(cm.Has(iana.CWTClaimReserved))

	vbool, err := cm.GetBool(iana.CWTClaimReserved)
	assert.NoError(err)
	assert.Equal(true, vbool)

	cm = ClaimsMap{iana.CWTClaimReserved: 1}
	vint, err := cm.GetInt(iana.CWTClaimReserved)
	assert.NoError(err)
	assert.Equal(1, vint)

	cm = ClaimsMap{iana.CWTClaimReserved: 1}
	vint64, err := cm.GetInt64(iana.CWTClaimReserved)
	assert.NoError(err)
	assert.Equal(int64(1), vint64)

	cm = ClaimsMap{iana.CWTClaimReserved: 1}
	vuint64, err := cm.GetUint64(iana.CWTClaimReserved)
	assert.NoError(err)
	assert.Equal(uint64(1), vuint64)

	cm = ClaimsMap{iana.CWTClaimReserved: []byte{1, 2, 3, 4}}
	vbytes, err := cm.GetBytes(iana.CWTClaimReserved)
	assert.NoError(err)
	assert.Equal([]byte{1, 2, 3, 4}, vbytes)

	cm = ClaimsMap{iana.CWTClaimReserved: "hello"}
	vstr, err := cm.GetString(iana.CWTClaimReserved)
	assert.NoError(err)
	assert.Equal("hello", vstr)

	var p *ClaimsMap
	assert.ErrorContains(p.UnmarshalCBOR([]byte{0xa0}), "nil IntMap")

	cm = ClaimsMap{
		iana.CWTClaimIss: "issuer",
		iana.CWTClaimSub: "subject",
		iana.CWTClaimAud: "audience",
	}

	data, err := key.MarshalCBOR(cm)
	assert.NoError(err)

	var cm2 ClaimsMap
	assert.NoError(cm2.UnmarshalCBOR(data))
	assert.Equal(data, cm2.Bytesify())

	var cm3 Claims
	assert.NoError(key.UnmarshalCBOR(data, &cm3))
	assert.Equal(data, cm3.Bytesify())

	cm = ClaimsMap{
		iana.CWTClaimIss:       "issuer",
		iana.CWTClaimSub:       "subject",
		iana.CWTClaimAud:       []string{"audience"},
		iana.CWTClaimExp:       1000,
		iana.CWTClaimCti:       []byte{1, 2, 3, 4},
		iana.CWTClaimEUPHNonce: []byte{5, 6, 7, 8},
	}

	data, err = key.MarshalCBOR(cm)
	assert.NoError(err)

	var cm4 ClaimsMap
	assert.NoError(cm4.UnmarshalCBOR(data))
	assert.Equal(data, cm4.Bytesify())
	nonce, _ := cm4.GetBytes(iana.CWTClaimEUPHNonce)
	assert.Equal([]byte{5, 6, 7, 8}, nonce)
}
