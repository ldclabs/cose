// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cose implements CBOR Object Signing and Encryption (COSE) as defined in RFC9052.
// https://datatracker.ietf.org/doc/html/rfc9052.
package cose

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// Headers represents a COSE Generic_Headers structure.
type Headers key.CoseMap

// Has returns true if the Headers has the given parameter.
func (h Headers) Has(p any) bool {
	return key.CoseMap(h).Has(p)
}

// Get returns the value of the given parameter.
func (h Headers) Get(p any) any {
	return key.CoseMap(h).Get(p)
}

// Set sets the parameter. parameter key should be int or string.
func (h Headers) Set(p, value any) error {
	return key.CoseMap(h).Set(p, value)
}

// GetBool returns the value of the given parameter as a bool, or a error.
func (h Headers) GetBool(p any) (bool, error) {
	return key.CoseMap(h).GetBool(p)
}

// GetInt returns the value of the given parameter as a int, or a error.
func (h Headers) GetInt(p any) (int, error) {
	return key.CoseMap(h).GetInt(p)
}

// GetInt64 returns the value of the given parameter as a int64, or a error.
func (h Headers) GetInt64(p any) (int64, error) {
	return key.CoseMap(h).GetInt64(p)
}

// GetUint64 returns the value of the given parameter as a uint64, or a error.
func (h Headers) GetUint64(p any) (uint64, error) {
	return key.CoseMap(h).GetUint64(p)
}

// GetBytes returns the value of the given parameter as a slice of bytes, or a error.
func (h Headers) GetBytes(p any) ([]byte, error) {
	return key.CoseMap(h).GetBytes(p)
}

// GetString returns the value of the given parameter as a string, or a error.
func (h Headers) GetString(p any) (string, error) {
	return key.CoseMap(h).GetString(p)
}

// GetMap returns the value of the given parameter as a key.CoseMap, or a error.
func (h Headers) GetMap(p any) (key.CoseMap, error) {
	return key.CoseMap(h).GetMap(p)
}

// MarshalCBOR implements the CBOR Marshaler interface for Headers.
func (h Headers) MarshalCBOR() ([]byte, error) {
	return key.CoseMap(h).MarshalCBOR()
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Headers.
func (h *Headers) UnmarshalCBOR(data []byte) error {
	return (*key.CoseMap)(h).UnmarshalCBOR(data)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (h Headers) Bytesify() []byte {
	return key.CoseMap(h).Bytesify()
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns ([]byte{}, nil) if Headers is nil or empty.
func (h Headers) Bytes() ([]byte, error) {
	if len(h) == 0 {
		return []byte{}, nil
	}
	return h.MarshalCBOR()
}

// HeadersFromBytes decode bytes into a Headers.
// It returns (Headers{}, nil) if data is nil or empty.
func HeadersFromBytes(data []byte) (Headers, error) {
	h := Headers{}
	if len(data) > 0 {
		if err := h.UnmarshalCBOR(data); err != nil {
			return nil, err
		}
	}

	return h, nil
}

// protectedHeadersFromBytes decodes an empty_or_serialized_map value and also
// returns the bytes that must be used in Sig_structure / Enc_structure /
// MAC_structure. RFC 9052 requires recipients to accept h'a0' on the wire for
// an empty protected map, but the authenticated structure uses an empty bstr
// in that case.
func protectedHeadersFromBytes(data []byte) (Headers, []byte, error) {
	h, err := HeadersFromBytes(data)
	if err != nil {
		return nil, nil, err
	}
	if len(h) == 0 {
		return h, []byte{}, nil
	}
	return h, data, nil
}

func headerBytes(protected, unprotected Headers, label any) ([]byte, bool, error) {
	if protected.Has(label) {
		v, err := protected.GetBytes(label)
		return v, true, err
	}
	if unprotected.Has(label) {
		v, err := unprotected.GetBytes(label)
		return v, true, err
	}
	return nil, false, nil
}

// checkHeaders validates a layer's protected and unprotected header buckets
// against the rules in RFC 9052 §3 and §3.1. It is called by the message,
// signature and recipient decoders after both buckets have been parsed.
//
// Reference:
//   - https://datatracker.ietf.org/doc/html/rfc9052#section-3
//   - https://datatracker.ietf.org/doc/html/rfc9052#section-3.1
func checkHeaders(protected, unprotected Headers) error {
	// §3.1: "When present, the 'crit' header parameter MUST be placed in the
	// protected-header-parameters bucket."
	if unprotected.Has(iana.HeaderParameterCrit) {
		return errors.New(`cose/cose: checkHeaders: "crit" header parameter MUST be in the protected bucket`)
	}

	// §3: "Applications SHOULD verify that the same label does not occur in both
	// the protected and unprotected header parameters." We reject such messages
	// as malformed so that attributes are never ambiguous.
	for label := range protected {
		if unprotected.Has(label) {
			return fmt.Errorf("cose/cose: checkHeaders: header parameter %v occurs in both protected and unprotected buckets", label)
		}
	}

	// §3.1: "The 'Initialization Vector' and 'Partial Initialization Vector'
	// header parameters MUST NOT both be present in the same security layer."
	hasIV := protected.Has(iana.HeaderParameterIV) || unprotected.Has(iana.HeaderParameterIV)
	hasPartialIV := protected.Has(iana.HeaderParameterPartialIV) || unprotected.Has(iana.HeaderParameterPartialIV)
	if hasIV && hasPartialIV {
		return errors.New("cose/cose: checkHeaders: both iv and partial iv are present")
	}

	// §3.1: the "crit" header parameter "array MUST have at least one value in
	// it", and "If the 'crit' value list includes a label for which the header
	// parameter is not in the protected-header-parameters bucket, this is a fatal
	// error in processing the message."
	if protected.Has(iana.HeaderParameterCrit) {
		crit, ok := normalizeCrit(protected.Get(iana.HeaderParameterCrit))
		if !ok {
			return errors.New(`cose/cose: checkHeaders: "crit" header parameter MUST be an array of int / tstr labels`)
		}
		if len(crit) == 0 {
			return errors.New(`cose/cose: checkHeaders: "crit" header parameter MUST have at least one value`)
		}
		for _, label := range crit {
			if !protected.Has(label) {
				return fmt.Errorf("cose/cose: checkHeaders: critical header parameter %v is not in the protected bucket", label)
			}
		}
	}

	return nil
}

// normalizeCrit converts the decoded "crit" value into a slice of labels
// (int or string) matching how Headers keys are stored, so that presence in
// the protected bucket can be checked. It returns ok=false when the value is
// not a valid array of int / tstr labels.
func normalizeCrit(v any) (labels []any, ok bool) {
	if _, isBytes := v.([]byte); isBytes {
		return nil, false
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		// continue
	default:
		return nil, false
	}

	labels = make([]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		e := rv.Index(i).Interface()
		if s, isStr := e.(string); isStr {
			labels = append(labels, s)
			continue
		}
		n, err := key.ToInt(e)
		if err != nil {
			return nil, false
		}
		labels = append(labels, n)
	}
	return labels, true
}
