// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"errors"
	"fmt"

	"github.com/ldclabs/cose/key"
)

// Recipient represents a COSE_recipient object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure.
type Recipient struct {
	Protected   Headers
	Unprotected Headers
	Ciphertext  []byte

	context    string // "Enc_Recipient", "Mac_Recipient", "Rec_Recipient"
	recipients []*Recipient
	mm         *recipientMessage0
}

// AddRecipient add a Recipient to the COSE_Recipient object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-two-layers-of-recipient-inf.
func (m *Recipient) AddRecipient(recipient *Recipient) error {
	if recipient == nil {
		return errors.New("cose/cose: Recipient.AddRecipient: nil Recipient")
	}
	if recipient == m {
		return errors.New("cose/cose: Recipient.AddRecipient: should not add itself")
	}
	if recipient.context != "" {
		return fmt.Errorf("cose/cose: Recipient.AddRecipient: should not have %q context",
			recipient.context)
	}

	if len(recipient.recipients) > 0 {
		return errors.New("cose/cose: Recipient.AddRecipient: should not have nested recipients")
	}

	if err := recipient.init(); err != nil {
		return err
	}

	recipient.context = "Rec_Recipient"
	m.recipients = append(m.recipients, recipient)
	return nil
}

func (m *Recipient) Recipients() []*Recipient {
	return m.recipients
}

func (m *Recipient) init() error {
	if m.mm != nil {
		return nil
	}

	if m.Protected == nil {
		m.Protected = Headers{}
	}
	if m.Unprotected == nil {
		m.Unprotected = Headers{}
	}
	mm := &recipientMessage0{
		Protected:   []byte{},
		Unprotected: m.Unprotected,
		Ciphertext:  m.Ciphertext,
	}
	if len(m.Protected) > 0 {
		protected, err := key.MarshalCBOR(m.Protected)
		if err != nil {
			return err
		}
		mm.Protected = protected
	}
	m.mm = mm
	return nil
}

// MarshalCBOR implements the CBOR Marshaler interface for Recipient.
func (m *Recipient) MarshalCBOR() ([]byte, error) {
	if err := m.init(); err != nil {
		return nil, err
	}

	if len(m.recipients) == 0 {
		return key.MarshalCBOR(m.mm)
	}

	mm := &recipientMessage{
		Protected:   m.mm.Protected,
		Unprotected: m.mm.Unprotected,
		Ciphertext:  m.mm.Ciphertext,
		Recipients:  m.recipients,
	}

	return key.MarshalCBOR(mm)
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Recipient.
func (m *Recipient) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: Recipient.UnmarshalCBOR: nil Recipient")
	}
	if len(data) == 0 {
		return errors.New("cose/cose: Recipient.UnmarshalCBOR: empty data")
	}

	switch data[0] {
	case 0x83: // array(3)
		mm := &recipientMessage0{}
		if err := key.UnmarshalCBOR(data, mm); err != nil {
			return err
		}

		protected := Headers{}
		if len(mm.Protected) > 0 {
			if err := key.UnmarshalCBOR(mm.Protected, &protected); err != nil {
				return err
			}
		}

		m.Protected = protected
		m.Unprotected = mm.Unprotected
		m.Ciphertext = mm.Ciphertext
		m.mm = mm

	case 0x84:
		mm := &recipientMessage{}
		if err := key.UnmarshalCBOR(data, mm); err != nil {
			return err
		}
		if len(mm.Recipients) == 0 {
			return errors.New("cose/cose: Recipient.UnmarshalCBOR: no recipients")
		}
		for _, r := range mm.Recipients {
			if r == nil {
				return errors.New("cose/cose: Recipient.UnmarshalCBOR: nil recipient")
			}
			if len(r.recipients) > 0 {
				return errors.New("cose/cose: Recipient.UnmarshalCBOR: should not have nested recipients")
			}
		}

		protected := Headers{}
		if len(mm.Protected) > 0 {
			if err := key.UnmarshalCBOR(mm.Protected, &protected); err != nil {
				return err
			}
		}

		m.Protected = protected
		m.Unprotected = mm.Unprotected
		m.Ciphertext = mm.Ciphertext
		m.recipients = mm.Recipients
		m.mm = &recipientMessage0{
			Protected:   mm.Protected,
			Unprotected: mm.Unprotected,
			Ciphertext:  mm.Ciphertext,
		}

	default:
		return errors.New("cose/cose: Recipient.UnmarshalCBOR: invalid data")
	}

	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *Recipient) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

// recipientMessage represents a COSE_recipient structure to encode and decode.
type recipientMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
	Recipients  []*Recipient
}

// recipientMessage0 represents a COSE_recipient structure without sub recipients to encode and decode.
type recipientMessage0 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
}
