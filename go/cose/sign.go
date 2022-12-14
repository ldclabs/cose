// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/go/key"
)

// SignMessage represents a COSE_Sign object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si
type SignMessage struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte

	sm *signMessage
}

// VerifySignMessage verifies and decodes a COSE_Sign format with some Verifiers and returns a *SignMessage.
// `externalData` should be the same as the one used in `SignMessage.SignAndEncode`.
func VerifySignMessage(verifiers key.Verifiers, coseData, externalData []byte) (*SignMessage, error) {
	s := &SignMessage{}
	if err := s.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := s.Verify(verifiers, externalData); err != nil {
		return nil, err
	}
	return s, nil
}

// SignAndEncode signs and encodes a COSE_Sign message with some Signers.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (s *SignMessage) SignAndEncode(signers key.Signers, externalData []byte) ([]byte, error) {
	if err := s.WithSign(signers, externalData); err != nil {
		return nil, err
	}

	return s.MarshalCBOR()
}

// signMessage represents a COSE_Sign structure to encode and decode.
type signMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // can be nil
	Signatures  []*Signature
}

// Signature represents a COSE_Signature object.
type Signature struct {
	Protected   Headers
	Unprotected Headers

	sm         *signatureMessage
	toBeSigned []byte
}

// WithSign signs a COSE_Sign message with some Signers.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (s *SignMessage) WithSign(signers key.Signers, externalData []byte) error {
	if len(signers) == 0 {
		return errors.New("cose/go/cose: SignMessage.WithSign: no signers")
	}

	if s.Protected == nil {
		s.Protected = Headers{}
	}

	if s.Unprotected == nil {
		s.Unprotected = Headers{}
	}

	sm := &signMessage{
		Protected:   []byte{},
		Unprotected: s.Unprotected,
		Payload:     s.Payload,
		Signatures:  make([]*Signature, 0, len(signers)),
	}

	var err error
	if len(s.Protected) > 0 {
		sm.Protected, err = key.MarshalCBOR(s.Protected)
		if err != nil {
			return err
		}
	}

	for _, signer := range signers {
		sig := &Signature{
			Protected:   Headers{},
			Unprotected: Headers{},
		}
		if alg := signer.Key().Alg(); alg != key.AlgReserved {
			sig.Protected[HeaderLabelAlgorithm] = alg
		}
		if kid := signer.Key().Kid(); len(kid) > 0 {
			sig.Unprotected[HeaderLabelKeyID] = kid
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

		sig.toBeSigned, err = sm.toBeSigned(sigm.Protected, externalData)
		if err != nil {
			return err
		}

		sigm.Signature, err = signer.Sign(sig.toBeSigned)
		if err != nil {
			return err
		}
		sig.sm = sigm
		sm.Signatures = append(sm.Signatures, sig)
	}

	s.sm = sm
	return nil
}

// Verify verifies a COSE_Sign message with some Verifiers.
// It should call `SignMessage.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used in SignMessage.WithSign.
func (s *SignMessage) Verify(verifiers key.Verifiers, externalData []byte) error {
	if len(verifiers) == 0 {
		return errors.New("cose/go/cose: SignMessage.Verify: no verifiers")
	}

	if s.sm == nil || s.sm.Signatures == nil {
		return errors.New("cose/go/cose: SignMessage.Verify: should call SignMessage.UnmarshalCBOR")
	}

	if len(s.sm.Signatures) == 0 {
		return errors.New("cose/go/cose: SignMessage.Verify: no signatures")
	}

	var err error
	for _, sig := range s.sm.Signatures {
		kid := sig.Kid()
		verifier := verifiers.Lookup(kid)
		if verifier == nil {
			return fmt.Errorf("cose/go/cose: SignMessage.Verify: no verifier for kid h'%s'", kid.String())
		}

		sig.toBeSigned, err = s.sm.toBeSigned(sig.sm.Protected, externalData)
		if err != nil {
			return err
		}
		if err = verifier.Verify(sig.toBeSigned, sig.Signature()); err != nil {
			return err
		}
	}

	return nil
}

func (sm *signMessage) toBeSigned(sign_protected, external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Sig_structure https://datatracker.ietf.org/doc/html/rfc9052#name-signing-and-verification-pr
	return key.MarshalCBOR([]any{
		"Signature",    // context
		sm.Protected,   // body_protected
		sign_protected, // sign_protected
		external_aad,   // external_aad
		sm.Payload,     // payload
	})
}

// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const cborTagCOSESign = 98

// MarshalCBOR implements the CBOR Marshaler interface for SignMessage.
// It should call `SignMessage.WithSign` before calling this method.
func (s *SignMessage) MarshalCBOR() ([]byte, error) {
	if s.sm == nil || s.sm.Signatures == nil {
		return nil, errors.New("cose/go/cose: SignMessage.MarshalCBOR: should call SignMessage.WithSign")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSESign,
		Content: s.sm,
	})
}

// signMessagePrefix represents the fixed prefix of COSE_Sign_Tagged.
var signMessagePrefix = []byte{
	0xd8, 0x62, // #6.98
	0x84, // Array of length 4
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for SignMessage.
func (s *SignMessage) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cose/go/cose: SignMessage.UnmarshalCBOR: nil SignMessage")
	}

	if !bytes.HasPrefix(data, signMessagePrefix) {
		return errors.New("cose/go/cose: SignMessage.UnmarshalCBOR: invalid COSE_Sign_Tagged object")
	}

	sm := &signMessage{}
	if err := key.UnmarshalCBOR(data[2:], sm); err != nil {
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
		return nil, errors.New("cose/go/cose: Signature.MarshalCBOR: should call SignMessage.WithSign")
	}

	return key.MarshalCBOR(s.sm)
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Signature.
func (s *Signature) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cose/go/cose: Signature.UnmarshalCBOR: nil Signature")
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

	kid, _ := key.IntMap(s.Unprotected).GetBytes(HeaderLabelKeyID)
	return kid
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (s *SignMessage) Bytesify() []byte {
	b, _ := s.MarshalCBOR()
	return b
}

// Signatures returns the signatures of the SignMessage.
// If the SignMessage is not signed, it returns nil.
func (s *SignMessage) Signatures() []*Signature {
	if s.sm == nil {
		return nil
	}
	return s.sm.Signatures
}
