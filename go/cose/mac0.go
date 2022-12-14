// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/go/key"
)

// Mac0Message represents a COSE_Mac0 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-signer
type Mac0Message struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte

	mm         *mac0Message
	toBeSigned []byte
}

// VerifyMac0Message verifies and decodes a COSE_Mac0 message with a MACer and returns a *Mac0Message.
// `externalData` should be the same as the one used in `Mac0Message.ComputeAndEncode`.
func VerifyMac0Message(macer key.MACer, coseData, externalData []byte) (*Mac0Message, error) {
	m := &Mac0Message{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Verify(macer, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// ComputeAndEncode computes and encodes a COSE_Mac0 message with a MACer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Mac0Message) ComputeAndEncode(macer key.MACer, externalData []byte) ([]byte, error) {
	if err := m.Compute(macer, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// mac0Message represents a COSE_Mac0 structure to encode and decode.
type mac0Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // can be nil
	Tag         []byte
}

// Compute computes a COSE_Mac0 message' MAC with a MACer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Mac0Message) Compute(macer key.MACer, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := macer.Key().Alg(); alg != key.AlgReserved {
			m.Protected[HeaderLabelAlgorithm] = alg
		}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := macer.Key().Kid(); len(kid) > 0 {
			m.Unprotected[HeaderLabelKeyID] = kid
		}
	}

	mm := &mac0Message{
		Protected:   []byte{},
		Unprotected: m.Unprotected,
		Payload:     m.Payload,
	}

	var err error
	if len(m.Protected) > 0 {
		mm.Protected, err = key.MarshalCBOR(m.Protected)
		if err != nil {
			return err
		}
	}

	m.toBeSigned, err = mm.toBeSigned(externalData)
	if err != nil {
		return err
	}

	if mm.Tag, err = macer.MACCreate(m.toBeSigned); err == nil {
		m.mm = mm
	}
	return err
}

// Verify verifies a COSE_Mac0 message' MAC with a MACer.
// It should call `Mac0Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used in Mac0Message.Compute.
func (m *Mac0Message) Verify(macer key.MACer, externalData []byte) error {
	if m.mm == nil || m.mm.Tag == nil {
		return errors.New("cose/go/cose: Mac0Message.Verify: should call Mac0Message.UnmarshalCBOR")
	}

	var err error
	m.toBeSigned, err = m.mm.toBeSigned(externalData)
	if err != nil {
		return err
	}

	return macer.MACVerify(m.toBeSigned, m.mm.Tag)
}

func (mm *mac0Message) toBeSigned(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// MAC_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-compute-and-verify-a
	return key.MarshalCBOR([]any{
		"MAC0",       // context
		mm.Protected, // body_protected
		external_aad, // external_aad
		mm.Payload,   // payload
	})
}

// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const cborTagCOSEMac0 = 17

// MarshalCBOR implements the CBOR Marshaler interface for Mac0Message.
// It should call `Mac0Message.WithSign` before calling this method.
func (m *Mac0Message) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Tag == nil {
		return nil, errors.New("cose/go/cose: Mac0Message.MarshalCBOR: should call Mac0Message.Compute")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSEMac0,
		Content: m.mm,
	})
}

// mac0MessagePrefix represents the fixed prefix of COSE_Mac0_Tagged.
var mac0MessagePrefix = []byte{
	0xd1, // #6.17
	0x84, // array of length 4
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Mac0Message.
func (s *Mac0Message) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cose/go/cose: Mac0Message.UnmarshalCBOR: nil Mac0Message")
	}
	// support untagged message
	if bytes.HasPrefix(data, mac0MessagePrefix) {
		data = data[1:]
	}

	mm := &mac0Message{}
	if err := key.UnmarshalCBOR(data, mm); err != nil {
		return err
	}

	protected := Headers{}
	if len(mm.Protected) > 0 {
		if err := key.UnmarshalCBOR(mm.Protected, &protected); err != nil {
			return err
		}
	}

	s.Protected = protected
	s.Unprotected = mm.Unprotected
	s.Payload = mm.Payload
	s.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (s *Mac0Message) Bytesify() []byte {
	b, _ := s.MarshalCBOR()
	return b
}

// Tag returns the MAC tag of the Mac0Message.
// If the MAC is not computed, it returns nil.
func (s *Mac0Message) Tag() []byte {
	if s.mm == nil {
		return nil
	}
	return s.mm.Tag
}
