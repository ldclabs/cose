// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"fmt"
	"math"
	"time"

	"github.com/ldclabs/cose/iana"
)

const (
	cwtMaxClockSkewMinutes = 10
)

// ValidatorOpts defines validation options for CWT validators.
type ValidatorOpts struct {
	ExpectedIssuer   string
	ExpectedAudience string

	AllowMissingExpiration bool
	ExpectIssuedInThePast  bool

	ClockSkew time.Duration
	FixedNow  time.Time
}

// Validator defines how CBOR Web Tokens (CWT) should be validated.
type Validator struct {
	opts ValidatorOpts
}

// NewValidator creates a new CWT Validator.
func NewValidator(opts *ValidatorOpts) (*Validator, error) {
	if opts == nil {
		return nil, fmt.Errorf("cose/cwt: NewValidator: nil ValidatorOpts")
	}

	if opts.ClockSkew.Minutes() > cwtMaxClockSkewMinutes {
		return nil, fmt.Errorf("cose/cwt: NewValidator: clock skew too large, expected <= %d minutes, got %f",
			cwtMaxClockSkewMinutes, opts.ClockSkew.Minutes())
	}
	return &Validator{
		opts: *opts,
	}, nil
}

// Validate validates a *Claims according to the options provided.
func (v *Validator) Validate(claims *Claims) error {
	if claims == nil {
		return fmt.Errorf("cose/cwt: Validator.Validate: nil Claims")
	}

	now := time.Now()
	if !v.opts.FixedNow.IsZero() {
		now = v.opts.FixedNow
	}

	if claims.Expiration == 0 && !v.opts.AllowMissingExpiration {
		return fmt.Errorf("cose/cwt: Validator.Validate: token doesn't have an expiration set")
	}

	if claims.Expiration > 0 {
		if !toTime(claims.Expiration).After(now.Add(-v.opts.ClockSkew)) {
			return fmt.Errorf("cose/cwt: Validator.Validate: token has expired")
		}
	}

	if claims.NotBefore > 0 {
		if t := toTime(claims.NotBefore); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("cose/cwt: Validator.Validate: token cannot be used yet")
		}
	}

	if claims.IssuedAt > 0 && v.opts.ExpectIssuedInThePast {
		if t := toTime(claims.IssuedAt); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid iat claim in the future")
		}
	}

	if v.opts.ExpectedIssuer != "" && v.opts.ExpectedIssuer != claims.Issuer {
		return fmt.Errorf("cose/cwt: Validator.Validate: issuer mismatch, expected %q, got %q",
			v.opts.ExpectedIssuer, claims.Issuer)
	}

	if v.opts.ExpectedAudience != "" && v.opts.ExpectedAudience != claims.Audience {
		return fmt.Errorf("cose/cwt: Validator.Validate: audience mismatch, expected %q, got %q",
			v.opts.ExpectedAudience, claims.Audience)
	}
	return nil
}

// ValidateMap validates a ClaimsMap according to the options provided.
func (v *Validator) ValidateMap(claims ClaimsMap) error {
	if claims == nil {
		return fmt.Errorf("cose/cwt: Validator.Validate: nil ClaimsMap")
	}

	now := time.Now()
	if !v.opts.FixedNow.IsZero() {
		now = v.opts.FixedNow
	}

	if !claims.Has(iana.CWTClaimExp) && !v.opts.AllowMissingExpiration {
		return fmt.Errorf("cose/cwt: Validator.Validate: token doesn't have an expiration set")
	}

	if claims.Has(iana.CWTClaimExp) {
		exp, err := claims.GetUint64(iana.CWTClaimExp)
		if err != nil {
			return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid exp claim, %w", err)
		}

		if !toTime(exp).After(now.Add(-v.opts.ClockSkew)) {
			return fmt.Errorf("cose/cwt: Validator.Validate: token has expired")
		}
	}

	if claims.Has(iana.CWTClaimNbf) {
		nbf, err := claims.GetUint64(iana.CWTClaimNbf)
		if err != nil {
			return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid nbf claim, %w", err)
		}
		if t := toTime(nbf); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("cose/cwt: Validator.Validate: token cannot be used yet")
		}
	}

	if claims.Has(iana.CWTClaimIat) {
		iat, err := claims.GetUint64(iana.CWTClaimIat)
		if err != nil {
			return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid iat claim, %w", err)
		}
		if iat > 0 && v.opts.ExpectIssuedInThePast {
			if t := toTime(iat); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
				return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid iat claim in the future")
			}
		}
	}

	iss, err := claims.GetString(iana.CWTClaimIss)
	if err != nil {
		return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid iss claim, %w", err)
	}
	if v.opts.ExpectedIssuer != "" && v.opts.ExpectedIssuer != iss {
		return fmt.Errorf("cose/cwt: Validator.Validate: issuer mismatch, expected %q, got %q",
			v.opts.ExpectedIssuer, iss)
	}

	aud, err := claims.GetString(iana.CWTClaimAud)
	if err != nil {
		return fmt.Errorf("cose/cwt: Validator.Validate: token has an invalid aud claim, %w", err)
	}
	if v.opts.ExpectedAudience != "" && v.opts.ExpectedAudience != aud {
		return fmt.Errorf("cose/cwt: Validator.Validate: audience mismatch, expected %q, got %q",
			v.opts.ExpectedAudience, aud)
	}

	return nil
}

func toTime(u uint64) time.Time {
	if u >= math.MaxInt64 {
		return time.Time{}
	}

	return time.Unix(int64(u), 0)
}
