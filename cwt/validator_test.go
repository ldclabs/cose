// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"math"
	"testing"
	"time"

	"github.com/ldclabs/cose/iana"
	_ "github.com/ldclabs/cose/key/ecdsa"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidator(t *testing.T) {

	t.Run("NewValidator", func(t *testing.T) {
		assert := assert.New(t)

		va, err := NewValidator(nil)
		assert.ErrorContains(err, "nil ValidatorOpts")
		assert.Nil(va)

		va, err = NewValidator(&ValidatorOpts{ClockSkew: time.Minute * 11})
		assert.ErrorContains(err, "clock skew too large")
		assert.Nil(va)

		va, err = NewValidator(&ValidatorOpts{})
		require.NoError(t, err)
		assert.ErrorContains(va.Validate(nil), "nil Claims")
		assert.ErrorContains(va.ValidateMap(nil), "nil ClaimsMap")
	})

	t.Run("Expiration", func(t *testing.T) {
		assert := assert.New(t)

		va, err := NewValidator(&ValidatorOpts{})
		require.NoError(t, err)
		assert.ErrorContains(va.Validate(&Claims{}), "token doesn't have an expiration set")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{}), "token doesn't have an expiration set")

		va, err = NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
		})
		require.NoError(t, err)
		assert.NoError(va.Validate(&Claims{}))
		assert.NoError(va.ValidateMap(ClaimsMap{}))
		assert.ErrorContains(va.Validate(&Claims{
			Expiration: 123,
		}), "token has expired")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimExp: "123",
		}), "token has an invalid exp claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimExp: 123,
		}), "token has expired")

		fixedNow := time.Unix(3600, 0)
		va, err = NewValidator(&ValidatorOpts{
			ClockSkew: time.Minute,
			FixedNow:  fixedNow,
		})
		require.NoError(t, err)
		assert.ErrorContains(va.Validate(&Claims{
			Expiration: uint64(fixedNow.Unix()) - 60,
		}), "token has expired")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimExp: uint64(fixedNow.Unix()) - 60,
		}), "token has expired")

		assert.NoError(va.Validate(&Claims{
			Expiration: uint64(fixedNow.Unix()) - 1,
		}))
		assert.NoError(va.ValidateMap(ClaimsMap{
			iana.CWTClaimExp: uint64(fixedNow.Unix()) - 1,
		}))
		assert.ErrorContains(va.Validate(&Claims{
			Expiration: math.MaxInt64,
		}), "token has expired")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimExp: math.MaxInt64,
		}), "token has expired")
	})

	t.Run("NotBefore", func(t *testing.T) {
		assert := assert.New(t)

		fixedNow := time.Unix(3600, 0)
		va, err := NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
			ClockSkew:              time.Minute,
			FixedNow:               fixedNow,
		})
		require.NoError(t, err)
		assert.ErrorContains(va.Validate(&Claims{
			NotBefore: uint64(fixedNow.Unix()) + 61,
		}), "token cannot be used yet")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimNbf: "123",
		}), "token has an invalid nbf claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimNbf: uint64(fixedNow.Unix()) + 61,
		}), "token cannot be used yet")

		assert.NoError(va.Validate(&Claims{
			NotBefore: uint64(fixedNow.Unix()) + 1,
		}))
		assert.NoError(va.ValidateMap(ClaimsMap{
			iana.CWTClaimNbf: uint64(fixedNow.Unix()) + 1,
		}))
	})

	t.Run("IssuedAt", func(t *testing.T) {
		assert := assert.New(t)

		fixedNow := time.Unix(3600, 0)
		va, err := NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
			ExpectIssuedInThePast:  true,
			ClockSkew:              time.Minute,
			FixedNow:               fixedNow,
		})
		require.NoError(t, err)
		assert.ErrorContains(va.Validate(&Claims{
			IssuedAt: uint64(fixedNow.Unix()) + 61,
		}), "token has an invalid iat claim in the future")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimIat: "123",
		}), "token has an invalid iat claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimIat: uint64(fixedNow.Unix()) + 61,
		}), "token has an invalid iat claim in the future")

		assert.NoError(va.Validate(&Claims{
			IssuedAt: uint64(fixedNow.Unix()) + 1,
		}))
		assert.NoError(va.ValidateMap(ClaimsMap{
			iana.CWTClaimIat: uint64(fixedNow.Unix()) + 1,
		}))
	})

	t.Run("ExpectedIssuer", func(t *testing.T) {
		assert := assert.New(t)

		va, err := NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
		})
		require.NoError(t, err)
		assert.NoError(va.Validate(&Claims{}))
		assert.NoError(va.ValidateMap(ClaimsMap{}))

		va, err = NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
			ExpectedIssuer:         "ldclabs",
		})
		require.NoError(t, err)

		assert.ErrorContains(va.Validate(&Claims{}),
			`issuer mismatch, expected "ldclabs", got ""`)
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimIss: 123,
		}), "token has an invalid iss claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{}),
			`issuer mismatch, expected "ldclabs", got ""`)

		assert.ErrorContains(va.Validate(&Claims{Issuer: "alice"}),
			`issuer mismatch, expected "ldclabs", got "alice"`)
		assert.ErrorContains(va.ValidateMap(ClaimsMap{iana.CWTClaimIss: 123}),
			"token has an invalid iss claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{iana.CWTClaimIss: "alice"}),
			`issuer mismatch, expected "ldclabs", got "alice"`)

		assert.NoError(va.Validate(&Claims{Issuer: "ldclabs"}))
		assert.NoError(va.ValidateMap(ClaimsMap{iana.CWTClaimIss: "ldclabs"}))
	})

	t.Run("ExpectedAudience", func(t *testing.T) {
		assert := assert.New(t)

		va, err := NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
		})
		require.NoError(t, err)
		assert.NoError(va.Validate(&Claims{}))
		assert.NoError(va.ValidateMap(ClaimsMap{}))

		va, err = NewValidator(&ValidatorOpts{
			AllowMissingExpiration: true,
			ExpectedAudience:       "ldclabs",
		})
		require.NoError(t, err)

		assert.ErrorContains(va.Validate(&Claims{}),
			`audience mismatch, expected "ldclabs", got ""`)
		assert.ErrorContains(va.ValidateMap(ClaimsMap{
			iana.CWTClaimAud: 123,
		}), "token has an invalid aud claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{}),
			`audience mismatch, expected "ldclabs", got ""`)

		assert.ErrorContains(va.Validate(&Claims{Audience: "alice"}),
			`audience mismatch, expected "ldclabs", got "alice"`)
		assert.ErrorContains(va.ValidateMap(ClaimsMap{iana.CWTClaimAud: 123}),
			"token has an invalid aud claim")
		assert.ErrorContains(va.ValidateMap(ClaimsMap{iana.CWTClaimAud: "alice"}),
			`audience mismatch, expected "ldclabs", got "alice"`)

		assert.NoError(va.Validate(&Claims{Audience: "ldclabs"}))
		assert.NoError(va.ValidateMap(ClaimsMap{iana.CWTClaimAud: "ldclabs"}))
	})
}
