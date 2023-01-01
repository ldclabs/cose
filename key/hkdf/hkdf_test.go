// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hkdf

import (
	"fmt"
	"testing"

	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHKDF256(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/hkdf-hmac-sha-examples
	for i, tc := range []struct {
		secret  []byte
		salt    []byte
		context []byte
		keySize int
		key     []byte
	}{
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			key.HexBytesify("840183F6F6F683F6F6F682188044A1013818"),
			16,
			key.HexBytesify("56074D506729CA40C4B4FE50C6439893"),
		},
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			key.HexBytesify("840383F6F6F683F6F6F68219010044A1013818"),
			32,
			key.HexBytesify("29CAA7326B683A73C98777707866D8838A3ADC3E3F46C180C54C5AAF01F1CC0C"),
		},
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			key.HexBytesify("840783F6F6F683F6F6F68219020044A1013818"),
			64,
			key.HexBytesify("69220077533E89BDA8DA04814ACCB4703E8C9B009033C8F6A7E65DBB3BCA621B2CF279C6842998CB2B4D2BBAD2E6652824F424D7B7004CC2D6A7384086CF5FF8"),
		},
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			nil,
			16,
			key.HexBytesify("0A9E2D1F080FDF6686C7DDE0DA3F113C"),
		},
	} {
		testmsg := fmt.Sprintf("test case %d", i)
		k, err := HKDF256(tc.secret, tc.salt, tc.context, tc.keySize)
		require.NoError(t, err, testmsg)
		assert.Equal(tc.key, k, testmsg)
	}

	_, err := HKDF256(key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"), nil, nil, 256*32)
	assert.ErrorContains(err, "entropy limit reached")
}

func TestHKDF512(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/hkdf-hmac-sha-examples
	for i, tc := range []struct {
		secret  []byte
		salt    []byte
		context []byte
		keySize int
		key     []byte
	}{
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			key.HexBytesify("840183F6F6F683F6F6F682188044A1013819"),
			16,
			key.HexBytesify("7EC6DB8FF17E392A6CB51579F8443976"),
		},
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			key.HexBytesify("840383F6F6F683F6F6F68219010044A1013819"),
			32,
			key.HexBytesify("4684AD00BE06914F7B74EE11F70E448D9192EE740182A674A665D7B4692A3EEB"),
		},
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			key.HexBytesify("840783F6F6F683F6F6F68219020044A1013819"),
			64,
			key.HexBytesify("ECEAACB6A84FC9FAD2BB2E2C9520A036675BD6894CE41E826E0A5BB98D22403163739A28A2FDFED93675BCC8E46F40EDBEA98D15834F01418A43382D54510DCB"),
		},
		{
			key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"),
			nil,
			nil,
			16,
			key.HexBytesify("C42FFE41AA6D378EB0BEFE47841D2E28"),
		},
	} {
		testmsg := fmt.Sprintf("test case %d", i)
		k, err := HKDF512(tc.secret, tc.salt, tc.context, tc.keySize)
		require.NoError(t, err, testmsg)
		assert.Equal(tc.key, k, testmsg)
	}

	_, err := HKDF512(key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"), nil, nil, 256*64)
	assert.ErrorContains(err, "entropy limit reached")
}

func TestHKDFAES(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/hkdf-aes-examples
	for i, tc := range []struct {
		secret  []byte
		context []byte
		keySize int
		key     []byte
	}{
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			key.HexBytesify("840A83F6F6F683F6F6F682188043A1012B"),
			16,
			key.HexBytesify("F0CCBAF836D73DA63ED8508EF966EEC9"),
		},
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			key.HexBytesify("840B83F6F6F683F6F6F68219010043A1012B"),
			32,
			key.HexBytesify("9F881DC284490E4C2133EBB6946EB6E2172B5B66A9D0E0862B1A7812165CED7F"),
		},
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			key.HexBytesify("840583F6F6F683F6F6F68219010043A1012B"),
			32,
			key.HexBytesify("C0DFE3BA00D222CC9FE1C90AA0EF88E7CDB1C67C6C1BE20C5746A909C23F5A6C"),
		},
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			key.HexBytesify("840783F6F6F683F6F6F68219020043A1012B"),
			64,
			key.HexBytesify("78FCC6C1395B8CFD3CBB893CCE3483A75B5D829DA2453B99C12E816186F7B95E65FC77C0C9C94495C22215CC6CCC1993893B224E5448B6310D3EC5CD6E1B1E49"),
		},
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			key.HexBytesify("840A834653656E646572F6F68349526563697069656E74F6F682188043A1012B"),
			16,
			key.HexBytesify("7CC520F4248B71FB43DECA848CAAB874"),
		},
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			key.HexBytesify("840A83F64453313031F683F64452313032F682188043A1012B"),
			16,
			key.HexBytesify("671BBD43EF98AA4B5D265FE93633EED3"),
		},
		{
			key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"),
			nil,
			16,
			key.HexBytesify("E76D66F01225020639F8DBD2EF3990AA"),
		},
	} {
		testmsg := fmt.Sprintf("test case %d", i)
		k, err := HKDFAES(tc.secret, tc.context, tc.keySize)
		require.NoError(t, err, testmsg)
		assert.Equal(tc.key, k, testmsg)
	}

	_, err := HKDFAES([]byte{1, 2, 3, 4}, nil, 256*16)
	assert.ErrorContains(err, "crypto/aes: invalid key size 4")

	_, err = HKDFAES(key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg"), nil, 256*16)
	assert.ErrorContains(err, "entropy limit reached")
}
