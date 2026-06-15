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

// RFC 9052 §3 and §3.1 header-parameter validation.
func TestCheckHeaders(t *testing.T) {
	assert := assert.New(t)

	// no crit and no collision -> ok
	assert.NoError(checkHeaders(
		Headers{iana.HeaderParameterAlg: iana.AlgorithmES256},
		Headers{iana.HeaderParameterKid: []byte("k")}))

	// nil buckets -> ok
	assert.NoError(checkHeaders(nil, nil))

	// §3.1: crit MUST be in the protected bucket
	assert.ErrorContains(checkHeaders(
		Headers{},
		Headers{iana.HeaderParameterCrit: []any{1}}),
		"MUST be in the protected bucket")

	// §3: the same label MUST NOT occur in both buckets
	assert.ErrorContains(checkHeaders(
		Headers{iana.HeaderParameterAlg: iana.AlgorithmES256},
		Headers{iana.HeaderParameterAlg: iana.AlgorithmES256}),
		"both protected and unprotected")

	// §3.1: crit MUST be an array of labels
	assert.ErrorContains(checkHeaders(
		Headers{iana.HeaderParameterCrit: 1}, Headers{}),
		"array of int / tstr")
	assert.ErrorContains(checkHeaders(
		Headers{iana.HeaderParameterCrit: []byte{1, 2}}, Headers{}),
		"array of int / tstr")

	// §3.1: crit MUST have at least one value
	assert.ErrorContains(checkHeaders(
		Headers{iana.HeaderParameterCrit: []any{}}, Headers{}),
		"at least one value")

	// §3.1: every crit label MUST be present in the protected bucket
	assert.ErrorContains(checkHeaders(
		Headers{iana.HeaderParameterCrit: []any{100}}, Headers{}),
		"not in the protected bucket")

	// crit referencing present int / int64 / string labels -> ok
	assert.NoError(checkHeaders(
		Headers{iana.HeaderParameterCrit: []any{int(100)}, 100: "x"}, Headers{}))
	assert.NoError(checkHeaders(
		Headers{iana.HeaderParameterCrit: []any{int64(100)}, 100: "x"}, Headers{}))
	assert.NoError(checkHeaders(
		Headers{iana.HeaderParameterCrit: []any{"foo"}, "foo": 1}, Headers{}))
}

// crit and collision must also be enforced through a real message decode.
func TestSign1CritDecode(t *testing.T) {
	assert := assert.New(t)

	encode := func(prot Headers, unprot map[any]any) []byte {
		pb, err := prot.Bytes()
		assert.NoError(err)
		return key.MustMarshalCBOR([]any{pb, unprot, []byte("payload"), []byte("sig")})
	}

	// crit references a label that is not in the protected bucket -> fatal error
	raw := encode(Headers{
		iana.HeaderParameterAlg:  iana.AlgorithmES256,
		iana.HeaderParameterCrit: []any{100},
	}, map[any]any{})
	var m1 Sign1Message[[]byte]
	assert.ErrorContains(m1.UnmarshalCBOR(raw), "not in the protected bucket")

	// the same label occurs in both buckets -> malformed
	raw = encode(Headers{
		iana.HeaderParameterAlg: iana.AlgorithmES256,
	}, map[any]any{iana.HeaderParameterAlg: iana.AlgorithmES256})
	var m2 Sign1Message[[]byte]
	assert.ErrorContains(m2.UnmarshalCBOR(raw), "both protected and unprotected")

	// crit references a label that IS present (alg) -> decodes fine
	raw = encode(Headers{
		iana.HeaderParameterAlg:  iana.AlgorithmES256,
		iana.HeaderParameterCrit: []any{iana.HeaderParameterAlg},
	}, map[any]any{})
	var m3 Sign1Message[[]byte]
	assert.NoError(m3.UnmarshalCBOR(raw))
	assert.True(m3.Protected.Has(iana.HeaderParameterCrit))
}

// COSE_Sign MUST carry at least one COSE_Signature (RFC 9052 §4.1).
func TestSignNoSignaturesDecode(t *testing.T) {
	assert := assert.New(t)

	// untagged COSE_Sign: [ h'' , {} , h'78' , [] ]
	empty := []byte{0x84, 0x40, 0xa0, 0x41, 0x78, 0x80}
	var m1 SignMessage[[]byte]
	assert.ErrorContains(m1.UnmarshalCBOR(empty), "no signatures")

	// untagged COSE_Sign with a nil signature entry: [ h'' , {} , h'78' , [null] ]
	nilSig := []byte{0x84, 0x40, 0xa0, 0x41, 0x78, 0x81, 0xf6}
	var m2 SignMessage[[]byte]
	assert.ErrorContains(m2.UnmarshalCBOR(nilSig), "nil Signature")
}
