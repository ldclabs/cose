// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// Sign1Message represents a COSE_Sign1 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-signer
type Sign1Message[T any] struct {
	Protected   Headers
	Unprotected Headers
	Payload     T

	mm *sign1Message
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
	}
	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := signer.Key().Kid(); len(kid) > 0 {
			m.Unprotected[iana.HeaderParameterKid] = kid
		}
	}

	mm := &sign1Message{
		Protected:   []byte{},
		Unprotected: m.Unprotected,
	}

	var err error
	if len(m.Protected) > 0 {
		mm.Protected, err = key.MarshalCBOR(m.Protected)
		if err != nil {
			return err
		}
	}

	switch v := any(m.Payload).(type) {
	case []byte:
		mm.Payload = v
	case cbor.RawMessage:
		mm.Payload = v
	default:
		mm.Payload, err = key.MarshalCBOR(m.Payload)
		if err != nil {
			return err
		}
	}

	toSign, err := mm.toSign(externalData)
	if err != nil {
		return err
	}

	if mm.Signature, err = signer.Sign(toSign); err == nil {
		m.mm = mm
	}
	return err
}

// Verify verifies a COSE_Sign1 message with a Verifier.
// It should call `Sign1Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used when signing.
func (m *Sign1Message[T]) Verify(verifier key.Verifier, externalData []byte) error {
	if m.mm == nil || m.mm.Signature == nil {
		return errors.New("cose/go/cose: Sign1Message.Verify: should call Sign1Message.UnmarshalCBOR")
	}

	toSign, err := m.mm.toSign(externalData)
	if err != nil {
		return err
	}

	return verifier.Verify(toSign, m.mm.Signature)
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
		return nil, errors.New("cose/go/cose: Sign1Message.MarshalCBOR: should call Sign1Message.WithSign")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  iana.CBORTagCOSESign1,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Sign1Message.
func (m *Sign1Message[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/go/cose: Sign1Message.UnmarshalCBOR: nil Sign1Message")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	if !bytes.HasPrefix(data, sign1MessagePrefix) {
		return errors.New("cose/go/cose: Sign1Message.UnmarshalCBOR: invalid COSE_Sign1_Tagged object")
	}

	mm := &sign1Message{}
	if err := key.UnmarshalCBOR(data[1:], mm); err != nil {
		return err
	}

	protected := Headers{}
	if len(mm.Protected) > 0 {
		if err := key.UnmarshalCBOR(mm.Protected, &protected); err != nil {
			return err
		}
	}

	if len(mm.Payload) > 0 {
		switch any(m.Payload).(type) {
		case []byte:
			m.Payload = any(mm.Payload).(T)
		case cbor.RawMessage:
			m.Payload = any(mm.Payload).(T)
		default:
			if err := key.UnmarshalCBOR(mm.Payload, &m.Payload); err != nil {
				return err
			}
		}
	}

	m.Protected = protected
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
