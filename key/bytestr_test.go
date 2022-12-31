// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestByteStr(t *testing.T) {
	assert := assert.New(t)

	bstr := ByteStr(GetRandomBytes(8))

	str := bstr.String()
	b64str := bstr.Base64()

	text, err := bstr.MarshalText()
	require.NoError(t, err)
	assert.Equal(str, string(text))

	jsonstr, err := json.Marshal(bstr)
	require.NoError(t, err)
	assert.Equal(`"`+str+`"`, string(jsonstr))

	data := HexBytesify(str)
	assert.Equal([]byte(bstr), data)

	data = Base64Bytesify(b64str)
	assert.Equal([]byte(bstr), data)
}

func TestHexBytesify(t *testing.T) {
	assert := assert.New(t)

	data := HexBytesify("az")
	assert.Nil(data)

	data = HexBytesify("0aff")
	assert.Equal([]byte{0x0a, 0xff}, data)
	assert.Equal(data, HexBytesify("0AFF"))
}

func TestBase64Bytesify(t *testing.T) {
	assert := assert.New(t)

	a := base64.URLEncoding.EncodeToString([]byte{0x0a, 0xff})
	b := base64.RawURLEncoding.EncodeToString([]byte{0x0a, 0xff})
	assert.NotEqual(a, b)

	assert.Equal([]byte{0x0a, 0xff}, Base64Bytesify(a))
	assert.Equal([]byte{0x0a, 0xff}, Base64Bytesify(b))
	assert.Nil(Base64Bytesify(a[1:]))
}

func TestSumKid(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(20, len(SumKid(nil)))
	assert.Equal(SumKid(nil), SumKid([]byte{}))

	assert.Equal(20, len(SumKid(GetRandomBytes(8))))
	assert.Equal(20, len(SumKid(GetRandomBytes(32))))
	assert.NotEqual(SumKid(GetRandomBytes(8)), SumKid(GetRandomBytes(8)))
}
