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

// SignMessage represents a COSE_Sign object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si
type SignMessage[T any] struct {
	// protected header parameters: iana.HeaderParameterAlg, iana.HeaderParameterCrit.
	Protected Headers
	// Other header parameters.
	Unprotected Headers
	// If payload is []byte or cbor.RawMessage,
	// it will not be encoded/decoded by key.MarshalCBOR/key.UnmarshalCBOR.
	Payload T

	mm *signMessage
}

// VerifySignMessage verifies and decodes a COSE_Sign format with some Verifiers and returns a *SignMessage.
// `externalData` should be the same as the one used when signing.
func VerifySignMessage[T any](verifiers key.Verifiers, coseData, externalData []byte) (*SignMessage[T], error) {
	m := &SignMessage[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Verify(verifiers, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// SignAndEncode signs and encodes a COSE_Sign message with some Signers.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *SignMessage[T]) SignAndEncode(signers key.Signers, externalData []byte) ([]byte, error) {
	if err := m.WithSign(signers, externalData); err != nil {
		return nil, err
	}

	return m.MarshalCBOR()
}

// Signature represents a COSE_Signature object.
type Signature struct {
	Protected   Headers
	Unprotected Headers

	sm     *signatureMessage
	toSign []byte
}

// WithSign signs a COSE_Sign message with some Signers.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *SignMessage[T]) WithSign(signers key.Signers, externalData []byte) error {
	if len(signers) == 0 {
		return errors.New("cose/cose: SignMessage.WithSign: no signers")
	}

	if m.Protected == nil {
		m.Protected = Headers{}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}
	}

	mm := &signMessage{
		Protected:   []byte{},
		Unprotected: m.Unprotected,
		Signatures:  make([]*Signature, 0, len(signers)),
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

	for _, signer := range signers {
		sig := &Signature{
			Protected:   Headers{},
			Unprotected: Headers{},
		}
		if alg := signer.Key().Alg(); alg != iana.AlgorithmReserved {
			sig.Protected[iana.HeaderParameterAlg] = alg
		}
		if kid := signer.Key().Kid(); len(kid) > 0 {
			sig.Unprotected[iana.HeaderParameterKid] = kid
		}

		sigm := &signatureMessage{
			Protected:   []byte{},
			Unprotected: sig.Unprotected,
		}
		if len(sig.Protected) > 0 {
			sigm.Protected, err = key.MarshalCBOR(sig.Protected)
			if err != nil {
				return err
			}
		}

		sig.toSign, err = mm.toSign(sigm.Protected, externalData)
		if err != nil {
			return err
		}

		sigm.Signature, err = signer.Sign(sig.toSign)
		if err != nil {
			return err
		}
		sig.sm = sigm
		mm.Signatures = append(mm.Signatures, sig)
	}

	m.mm = mm
	return nil
}

// Verify verifies a COSE_Sign message with some Verifiers.
// It should call `SignMessage.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used when signing.
func (m *SignMessage[T]) Verify(verifiers key.Verifiers, externalData []byte) error {
	if len(verifiers) == 0 {
		return errors.New("cose/cose: SignMessage.Verify: no verifiers")
	}

	if m.mm == nil || m.mm.Signatures == nil {
		return errors.New("cose/cose: SignMessage.Verify: should call SignMessage.UnmarshalCBOR")
	}

	if len(m.mm.Signatures) == 0 {
		return errors.New("cose/cose: SignMessage.Verify: no signatures")
	}

	var err error
	for _, sig := range m.mm.Signatures {
		kid := sig.Kid()
		verifier := verifiers.Lookup(kid)
		if verifier == nil {
			return fmt.Errorf("cose/cose: SignMessage.Verify: no verifier for kid h'%s'", kid.String())
		}

		sig.toSign, err = m.mm.toSign(sig.sm.Protected, externalData)
		if err != nil {
			return err
		}
		if err = verifier.Verify(sig.toSign, sig.Signature()); err != nil {
			return err
		}
	}

	return nil
}

// signMessage represents a COSE_Sign structure to encode and decode.
type signMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // can be nil
	Signatures  []*Signature
}

func (mm *signMessage) toSign(sign_protected, external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Sig_structure https://datatracker.ietf.org/doc/html/rfc9052#name-signing-and-verification-pr
	return key.MarshalCBOR([]any{
		"Signature",    // context
		mm.Protected,   // body_protected
		sign_protected, // sign_protected
		external_aad,   // external_aad
		mm.Payload,     // payload
	})
}

// MarshalCBOR implements the CBOR Marshaler interface for SignMessage.
// It should call `SignMessage.WithSign` before calling this method.
func (m *SignMessage[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Signatures == nil {
		return nil, errors.New("cose/cose: SignMessage.MarshalCBOR: should call SignMessage.WithSign")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  iana.CBORTagCOSESign,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for SignMessage.
func (m *SignMessage[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: SignMessage.UnmarshalCBOR: nil SignMessage")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	if bytes.HasPrefix(data, signMessagePrefix) {
		data = data[2:]
	}

	mm := &signMessage{}
	if err := key.UnmarshalCBOR(data, mm); err != nil {
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

// signatureMessage represents a COSE_Signature structure to encode and decode.
type signatureMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Signature   []byte
}

// MarshalCBOR implements the CBOR Marshaler interface for Signature.
func (s *Signature) MarshalCBOR() ([]byte, error) {
	if s.sm == nil || s.sm.Signature == nil {
		return nil, errors.New("cose/cose: Signature.MarshalCBOR: should call SignMessage.WithSign")
	}

	return key.MarshalCBOR(s.sm)
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Signature.
func (s *Signature) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cose/cose: Signature.UnmarshalCBOR: nil Signature")
	}

	sm := &signatureMessage{}
	if err := key.UnmarshalCBOR(data, sm); err != nil {
		return err
	}

	protected := Headers{}
	if len(sm.Protected) > 0 {
		if err := key.UnmarshalCBOR(sm.Protected, &protected); err != nil {
			return err
		}
	}

	s.Protected = protected
	s.Unprotected = sm.Unprotected
	s.sm = sm
	return nil
}

// Signature returns the signature of the Signature.
// If the SignMessage is not signed, it returns nil.
func (s *Signature) Signature() []byte {
	if s.sm == nil {
		return nil
	}
	return s.sm.Signature
}

// Kid returns the kid of the Signature which key signed.
// If the SignMessage is not signed, it returns nil.
func (s *Signature) Kid() key.ByteStr {
	if s.sm == nil {
		return nil
	}

	kid, _ := key.IntMap(s.Unprotected).GetBytes(iana.HeaderParameterKid)
	return kid
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *SignMessage[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

// Signatures returns the signatures of the SignMessage.
// If the SignMessage is not signed, it returns nil.
func (m *SignMessage[t]) Signatures() []*Signature {
	if m.mm == nil {
		return nil
	}
	return m.mm.Signatures
}
