// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
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

// ValidatorOpts define validation options for CWT validators.
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
		return nil, fmt.Errorf("cose/go/cwt: NewValidator: ValidatorOpts can't be nil")
	}

	if opts.ClockSkew.Minutes() > cwtMaxClockSkewMinutes {
		return nil, fmt.Errorf("cose/go/cwt: NewValidator: clock skew too large, max is %d minutes", cwtMaxClockSkewMinutes)
	}
	return &Validator{
		opts: *opts,
	}, nil
}

// Validate validates a *Claims according to the options provided.
func (v *Validator) Validate(claims *Claims) error {
	if claims == nil {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: claims can't be nil")
	}

	now := time.Now()
	if !v.opts.FixedNow.IsZero() {
		now = v.opts.FixedNow
	}

	if claims.Expiration == 0 && !v.opts.AllowMissingExpiration {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: token doesn't have an expiration set")
	}

	if claims.Expiration > 0 {
		if !toTime(claims.Expiration).After(now.Add(-v.opts.ClockSkew)) {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token has expired")
		}
	}

	if claims.NotBefore > 0 {
		if t := toTime(claims.NotBefore); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token cannot be used yet")
		}
	}

	if claims.IssuedAt > 0 && v.opts.ExpectIssuedInThePast {
		if t := toTime(claims.IssuedAt); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid iat claim in the future")
		}
	}

	if v.opts.ExpectedIssuer != "" && v.opts.ExpectedIssuer != claims.Issuer {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: validating issuer claim: got %s, want %s", claims.Issuer, v.opts.ExpectedIssuer)
	}

	if v.opts.ExpectedAudience != "" && v.opts.ExpectedAudience != claims.Audience {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: validating audience claim: got %s, want %s", claims.Audience, v.opts.ExpectedAudience)
	}
	return nil
}

// ValidateMap validates a ClaimsMap according to the options provided.
func (v *Validator) ValidateMap(claims ClaimsMap) error {
	if claims == nil {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: claims can't be nil")
	}

	now := time.Now()
	if !v.opts.FixedNow.IsZero() {
		now = v.opts.FixedNow
	}

	if !claims.Has(iana.CWTClaimExp) && !v.opts.AllowMissingExpiration {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: token doesn't have an expiration set")
	}

	if claims.Has(iana.CWTClaimExp) {
		exp, err := claims.GetUint64(iana.CWTClaimExp)
		if err != nil {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid exp claim, %v", err)
		}

		if !toTime(exp).After(now.Add(-v.opts.ClockSkew)) {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token has expired")
		}
	}

	if claims.Has(iana.CWTClaimNbf) {
		nbf, err := claims.GetUint64(iana.CWTClaimNbf)
		if err != nil {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid nbf claim, %v", err)
		}
		if t := toTime(nbf); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token cannot be used yet")
		}
	}

	if claims.Has(iana.CWTClaimIat) {
		iat, err := claims.GetUint64(iana.CWTClaimIat)
		if err != nil {
			return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid iat claim, %v", err)
		}
		if iat > 0 && v.opts.ExpectIssuedInThePast {
			if t := toTime(iat); t.IsZero() || t.After(now.Add(v.opts.ClockSkew)) {
				return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid iat claim in the future")
			}
		}
	}

	iss, err := claims.GetString(iana.CWTClaimIss)
	if err != nil {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid iss claim, %v", err)
	}
	if v.opts.ExpectedIssuer != "" && v.opts.ExpectedIssuer != iss {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: validating issuer claim: got %s, want %s", iss, v.opts.ExpectedIssuer)
	}

	aud, err := claims.GetString(iana.CWTClaimAud)
	if err != nil {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: token has an invalid aud claim, %v", err)
	}
	if v.opts.ExpectedAudience != "" && v.opts.ExpectedAudience != aud {
		return fmt.Errorf("cose/go/cwt: Validator.Validate: validating issuer claim: got %s, want %s", iss, v.opts.ExpectedAudience)
	}

	return nil
}

func toTime(u uint64) time.Time {
	if u >= math.MaxInt64 {
		return time.Time{}
	}

	return time.Unix(int64(u), 0)
}
