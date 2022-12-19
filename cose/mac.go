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

// MacMessage represents a COSE_Mac object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-maced-message-with-recipien
type MacMessage[T any] struct {
	Protected   Headers
	Unprotected Headers
	Payload     T

	recipients []*Recipient
	mm         *macMessage
	toMac      []byte
}

// VerifyMacMessage verifies and decodes a COSE_Mac message with a MACer and returns a *MacMessage.
// `externalData` should be the same as the one used when computing.
func VerifyMacMessage[T any](macer key.MACer, coseData, externalData []byte) (*MacMessage[T], error) {
	m := &MacMessage[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Verify(macer, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// ComputeAndEncode computes and encodes a COSE_Mac message with a MACer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *MacMessage[T]) ComputeAndEncode(macer key.MACer, externalData []byte) ([]byte, error) {
	if err := m.Compute(macer, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// AddRecipient add a Recipient to the COSE_Mac message.
func (m *MacMessage[T]) AddRecipient(recipient *Recipient) error {
	if recipient == nil {
		return errors.New("cose/go/cose: MacMessage.AddRecipient: nil recipient")
	}

	if err := recipient.init(); err != nil {
		return err
	}

	recipient.context = "Mac_Recipient"
	m.recipients = append(m.recipients, recipient)
	return nil
}

// Recipients returns recipients in the COSE_Mac message
func (m *MacMessage[T]) Recipients() []*Recipient {
	return m.recipients
}

// Compute computes a COSE_Mac message' MAC with a MACer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *MacMessage[T]) Compute(macer key.MACer, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := macer.Key().Alg(); alg != iana.AlgorithmReserved {
			m.Protected[iana.HeaderParameterAlg] = alg
		}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := macer.Key().Kid(); len(kid) > 0 {
			m.Unprotected[iana.HeaderParameterKid] = kid
		}
	}

	mm := &macMessage{
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

	m.toMac, err = mm.toMac(externalData)
	if err != nil {
		return err
	}

	if mm.Tag, err = macer.MACCreate(m.toMac); err == nil {
		m.mm = mm
	}
	return err
}

// Verify verifies a COSE_Mac message' MAC with a MACer.
// It should call `MacMessage.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used when computing.
func (m *MacMessage[T]) Verify(macer key.MACer, externalData []byte) error {
	if m.mm == nil || m.mm.Tag == nil {
		return errors.New("cose/go/cose: MacMessage.Verify: should call MacMessage.UnmarshalCBOR")
	}

	var err error
	m.toMac, err = m.mm.toMac(externalData)
	if err != nil {
		return err
	}

	return macer.MACVerify(m.toMac, m.mm.Tag)
}

// macMessage represents a COSE_Mac structure to encode and decode.
type macMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // can be nil
	Tag         []byte
	Recipients  []*Recipient
}

func (mm *macMessage) toMac(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// MAC_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-compute-and-verify-a
	return key.MarshalCBOR([]any{
		"MAC",        // context
		mm.Protected, // body_protected
		external_aad, // external_aad
		mm.Payload,   // payload
	})
}

// MarshalCBOR implements the CBOR Marshaler interface for MacMessage.
// It should call `MacMessage.WithSign` before calling this method.
func (m *MacMessage[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Tag == nil {
		return nil, errors.New("cose/go/cose: MacMessage.MarshalCBOR: should call MacMessage.Compute")
	}

	m.mm.Recipients = m.recipients
	return key.MarshalCBOR(cbor.Tag{
		Number:  iana.CBORTagCOSEMac,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for MacMessage.
func (m *MacMessage[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/go/cose: MacMessage.UnmarshalCBOR: nil MacMessage")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	// support untagged message
	if bytes.HasPrefix(data, macMessagePrefix) {
		data = data[1:]
	}

	mm := &macMessage{}
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
	m.recipients = mm.Recipients
	m.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *MacMessage[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

// Tag returns the MAC tag of the MacMessage.
// If the MAC is not computed, it returns nil.
func (m *MacMessage[T]) Tag() []byte {
	if m.mm == nil {
		return nil
	}
	return m.mm.Tag
}
