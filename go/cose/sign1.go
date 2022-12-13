// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/ldclabs/cose/go/key"
)

// Sign1Message represents a COSE_Sign1 object to be signed or verified.
//
// Reference https://datatracker.ietf.org/doc/html/rfc8152#section-4-2
type Sign1Message struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte

	sm *sign1Message
}

// VerifySign1Message verifies and decodes a COSE_Sign1 message with a verifier and returns a *Sign1Message.
// externalData should be the same as the one used in Sign1Message.SignAndEncode.
// It can be nil. https://datatracker.ietf.org/doc/html/rfc8152#section-4-3
func VerifySign1Message(verifier key.Verifier, coseData, externalData []byte) (*Sign1Message, error) {
	s := &Sign1Message{}
	if err := s.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := s.Verify(verifier, externalData); err != nil {
		return nil, err
	}
	return s, nil
}

// SignAndEncode signs and encodes a COSE_Sign1 message with a signer.
// externalData can be nil. https://datatracker.ietf.org/doc/html/rfc8152#section-4-3
func (s *Sign1Message) SignAndEncode(signer key.Signer, externalData []byte) ([]byte, error) {
	if err := s.WithSign(signer, externalData); err != nil {
		return nil, err
	}
	return s.MarshalCBOR()
}

// sign1Message represents a COSE_Sign1 structure.
type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // bstr / nil
	Signature   []byte
}

// WithSign signs a COSE_Sign1 message with a signer.
// externalData can be nil. https://datatracker.ietf.org/doc/html/rfc8152#section-4-3
func (s *Sign1Message) WithSign(signer key.Signer, externalData []byte) error {
	if s.Protected == nil {
		s.Protected = Headers{}
	}
	if s.Unprotected == nil {
		s.Unprotected = Headers{}
	}

	if alg := signer.Key().Alg(); alg != key.AlgReserved {
		s.Protected[HeaderLabelAlgorithm] = alg
	}

	if kid := signer.Key().Kid(); len(kid) > 0 {
		s.Unprotected[HeaderLabelKeyID] = kid
	}

	sm := &sign1Message{
		Protected:   []byte{},
		Unprotected: s.Unprotected,
		Payload:     s.Payload,
	}

	var err error
	if len(s.Protected) > 0 {
		sm.Protected, err = key.MarshalCBOR(s.Protected)
		if err != nil {
			return err
		}
	}

	toBeSigned, err := sm.toBeSigned(externalData)
	if err != nil {
		return err
	}

	if sm.Signature, err = signer.Sign(toBeSigned); err == nil {
		s.sm = sm
	}
	return err
}

// Verify verifies a COSE_Sign1 message with a verifier.
// It should call Sign1Message.UnmarshalCBOR before calling this method.
// externalData should be the same as the one used in Sign1Message.WithSign.
// It can be nil. https://datatracker.ietf.org/doc/html/rfc8152#section-4-3
func (s *Sign1Message) Verify(verifier key.Verifier, externalData []byte) error {
	if s.sm == nil || s.sm.Signature == nil {
		return errors.New("cose/go/cose: Sign1Message.Verify: should call Sign1Message.UnmarshalCBOR")
	}

	toBeSigned, err := s.sm.toBeSigned(externalData)
	if err != nil {
		return err
	}

	return verifier.Verify(toBeSigned, s.sm.Signature)
}

func (sm *sign1Message) toBeSigned(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Sig_structure https://datatracker.ietf.org/doc/html/rfc8152#section-4-4
	return key.MarshalCBOR([]any{
		"Signature1", // context
		sm.Protected, // body_protected
		external_aad, // external_aad
		sm.Payload,   // payload
	})
}

// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const cborTagCOSESign1 = 18

// MarshalCBOR implements the CBOR Marshaler interface for Sign1Message.
// It should call Sign1Message.WithSign before calling this method.
func (s *Sign1Message) MarshalCBOR() ([]byte, error) {
	if s.sm == nil || s.sm.Signature == nil {
		return nil, errors.New("cose/go/cose: Sign1Message.MarshalCBOR: should call Sign1Message.WithSign")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSESign1,
		Content: s.sm,
	})
}

// sign1MessagePrefix represents the fixed prefix of COSE_Sign1_Tagged.
var sign1MessagePrefix = []byte{
	0xd2, // #6.18
	0x84, // array of length 4
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Sign1Message.
func (s *Sign1Message) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cose/go/cose: Sign1Message.UnmarshalCBOR: nil Sign1Message")
	}

	if !bytes.HasPrefix(data, sign1MessagePrefix) {
		return errors.New("cose/go/cose: Sign1Message.UnmarshalCBOR: invalid COSE_Sign1_Tagged object")
	}

	sm := &sign1Message{}
	if err := key.UnmarshalCBOR(data[1:], sm); err != nil {
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
	s.Payload = sm.Payload
	s.sm = sm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (s *Sign1Message) Bytesify() []byte {
	b, _ := s.MarshalCBOR()
	return b
}

// Signature returns the signature of the Sign1Message.
// If the Sign1Message is not signed, it returns nil.
func (s *Sign1Message) Signature() []byte {
	if s.sm == nil {
		return nil
	}
	return s.sm.Signature
}
