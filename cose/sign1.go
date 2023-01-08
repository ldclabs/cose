// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// Sign1Message represents a COSE_Sign1 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-signer
type Sign1Message[T any] struct {
	// protected header parameters: iana.HeaderParameterAlg, iana.HeaderParameterCrit.
	Protected Headers
	// Other header parameters.
	Unprotected Headers
	// If payload is []byte or cbor.RawMessage,
	// it will not be encoded/decoded by key.MarshalCBOR/key.UnmarshalCBOR.
	Payload T

	mm     *sign1Message
	toSign []byte
}

// VerifySign1Message verifies and decodes a COSE_Sign1 message with a Verifier and returns a *Sign1Message.
// `externalData` should be the same as the one used when signing.
func VerifySign1Message[T any](verifier key.Verifier, coseData, externalData []byte) (*Sign1Message[T], error) {
	m := &Sign1Message[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Verify(verifier, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// SignAndEncode signs and encodes a COSE_Sign1 message with a Signer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Sign1Message[T]) SignAndEncode(signer key.Signer, externalData []byte) ([]byte, error) {
	if err := m.WithSign(signer, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// WithSign signs a COSE_Sign1 message with a Signer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Sign1Message[T]) WithSign(signer key.Signer, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := signer.Key().Alg(); alg != iana.AlgorithmReserved {
			m.Protected[iana.HeaderParameterAlg] = alg
		}
	} else if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ := m.Protected.GetInt(iana.HeaderParameterAlg)
		if alg != int(signer.Key().Alg()) {
			return fmt.Errorf("cose/cose: Sign1Message.WithSign: signer'alg mismatch, expected %d, got %d",
				alg, signer.Key().Alg())
		}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := signer.Key().Kid(); len(kid) > 0 {
			m.Unprotected[iana.HeaderParameterKid] = kid
		}
	}

	mm := &sign1Message{
		Unprotected: m.Unprotected,
	}

	var err error
	if mm.Protected, err = m.Protected.Bytes(); err != nil {
		return err
	}

	switch v := any(m.Payload).(type) {
	case []byte:
		mm.Payload = v
	case cbor.RawMessage:
		mm.Payload = v
	default:
		if mm.Payload, err = key.MarshalCBOR(m.Payload); err != nil {
			return err
		}
	}

	if m.toSign, err = mm.toSign(externalData); err != nil {
		return err
	}

	if mm.Signature, err = signer.Sign(m.toSign); err == nil {
		m.mm = mm
	}
	return err
}

// Verify verifies a COSE_Sign1 message with a Verifier.
// It should call `Sign1Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used when signing.
func (m *Sign1Message[T]) Verify(verifier key.Verifier, externalData []byte) error {
	if m.mm == nil || m.mm.Signature == nil {
		return errors.New("cose/cose: Sign1Message.Verify: should call Sign1Message.UnmarshalCBOR")
	}

	if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ := m.Protected.GetInt(iana.HeaderParameterAlg)
		if alg != int(verifier.Key().Alg()) {
			return fmt.Errorf("cose/cose: Sign1Message.Verify: verifier'alg mismatch, expected %d, got %d",
				alg, verifier.Key().Alg())
		}
	}

	var err error
	if m.toSign, err = m.mm.toSign(externalData); err != nil {
		return err
	}

	return verifier.Verify(m.toSign, m.mm.Signature)
}

// sign1Message represents a COSE_Sign1 structure to encode and decode.
type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // can be nil
	Signature   []byte
}

func (mm *sign1Message) toSign(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Sig_structure https://datatracker.ietf.org/doc/html/rfc9052#name-signing-and-verification-pr
	return key.MarshalCBOR([]any{
		"Signature1", // context
		mm.Protected, // body_protected
		external_aad, // external_aad
		mm.Payload,   // payload
	})
}

// MarshalCBOR implements the CBOR Marshaler interface for Sign1Message.
// It should call `Sign1Message.WithSign` before calling this method.
func (m *Sign1Message[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Signature == nil {
		return nil, errors.New("cose/cose: Sign1Message.MarshalCBOR: should call Sign1Message.WithSign")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  iana.CBORTagCOSESign1,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Sign1Message.
func (m *Sign1Message[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: Sign1Message.UnmarshalCBOR: nil Sign1Message")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	if bytes.HasPrefix(data, sign1MessagePrefix) {
		data = data[1:]
	}

	var err error
	mm := &sign1Message{}
	if err = key.UnmarshalCBOR(data, mm); err != nil {
		return err
	}

	if m.Protected, err = HeadersFromBytes(mm.Protected); err != nil {
		return err
	}

	if len(mm.Payload) > 0 {
		switch any(m.Payload).(type) {
		case []byte:
			m.Payload = any(mm.Payload).(T)
		case cbor.RawMessage:
			m.Payload = any(cbor.RawMessage(mm.Payload)).(T)
		default:
			if err := key.UnmarshalCBOR(mm.Payload, &m.Payload); err != nil {
				return err
			}
		}
	}

	m.Unprotected = mm.Unprotected
	m.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *Sign1Message[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

// Signature returns the signature of the Sign1Message.
// If the Sign1Message is not signed, it returns nil.
func (m *Sign1Message[T]) Signature() []byte {
	if m.mm == nil {
		return nil
	}
	return m.mm.Signature
}
