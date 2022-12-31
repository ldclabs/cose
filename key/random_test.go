// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRandomBytes(t *testing.T) {
	assert := assert.New(t)

	data := GetRandomBytes(8)
	assert.Equal(8, len(data))

	data2 := GetRandomBytes(8)
	assert.Equal(8, len(data))

	assert.NotEqual(data, data2)
}

func TestGetRandomUint32(t *testing.T) {
	assert := assert.New(t)

	u1 := GetRandomUint32()
	u2 := GetRandomUint32()
	assert.NotEqual(u1, u2)
}
