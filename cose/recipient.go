// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"errors"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// Recipient represents a COSE_recipient object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure
type Recipient struct {
	Protected   Headers
	Unprotected Headers
	Plaintext   []byte

	context    string // "Enc_Recipient", "Mac_Recipient", "Rec_Recipient"
	recipients []*Recipient
	mm         *recipientMessage0
}

func (m *Recipient) AddRecipient(recipient *Recipient) error {
	if recipient == nil {
		return errors.New("cose/cose: Recipient.AddRecipient: recipient is nil")
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

// Encrypt encrypt a COSE_Encrypt0 message with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Recipient) Encrypt(encryptor key.Encryptor, externalData []byte) error {
	if err := m.init(); err != nil {
		return err
	}

	iv, err := m.Unprotected.GetBytes(iana.HeaderParameterIV)
	if err != nil {
		return err
	}

	if len(iv) == 0 {
		iv := key.GetRandomBytes(uint16(encryptor.NonceSize()))
		m.Unprotected[iana.HeaderParameterIV] = iv
	}

	toEnc, err := m.mm.toEnc(m.context, externalData)
	if err != nil {
		return err
	}
	m.mm.Ciphertext, err = encryptor.Encrypt(iv, m.Plaintext, toEnc)
	return err
}

// Decrypt decrypts a COSE_Encrypt0 message with a Encryptor.
// It should call `Encrypt0Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used in Encrypt0Message.Encrypt.
func (m *Recipient) Decrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.mm == nil || m.mm.Ciphertext == nil {
		return errors.New("cose/cose: Encrypt0Message.Decrypt: should call Encrypt0Message.UnmarshalCBOR")
	}

	iv, err := m.Unprotected.GetBytes(iana.HeaderParameterIV)
	if err != nil {
		return err
	}

	toEnc, err := m.mm.toEnc(m.context, externalData)
	if err != nil {
		return err
	}

	m.Plaintext, err = encryptor.Decrypt(iv, m.mm.Ciphertext, toEnc)
	return err
}

// MarshalCBOR implements the CBOR Marshaler interface for Encrypt0Message.
// It should call `Encrypt0Message.Encrypt` before calling this method.
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
		Recipients:  make([]*recipientMessage0, len(m.recipients)),
	}
	for i := range m.recipients {
		mm.Recipients[i] = m.recipients[i].mm
	}

	return key.MarshalCBOR(mm)
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Mac0Message.
func (m *Recipient) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: Encrypt0Message.UnmarshalCBOR: nil Encrypt0Message")
	}
	if len(data) == 0 {
		return errors.New("cose/cose: Encrypt0Message.UnmarshalCBOR: empty data")
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
		m.mm = mm

	case 0x84:
		mm := &recipientMessage{}
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
		m.mm = &recipientMessage0{
			Protected:   mm.Protected,
			Unprotected: mm.Unprotected,
			Ciphertext:  mm.Ciphertext,
		}

		m.recipients = make([]*Recipient, len(mm.Recipients))
		for i := range mm.Recipients {
			m.recipients[i] = &Recipient{
				Protected:   Headers{},
				Unprotected: mm.Recipients[i].Unprotected,
				mm:          mm.Recipients[i],
			}
			if len(mm.Recipients[i].Protected) > 0 {
				if err := key.UnmarshalCBOR(mm.Recipients[i].Protected, &m.recipients[i].Protected); err != nil {
					return err
				}
			}
		}

	default:
		return errors.New("cose/cose: Encrypt0Message.UnmarshalCBOR: invalid data")
	}

	return nil
}

// recipientMessage represents a COSE_recipient structure to encode and decode.
type recipientMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
	Recipients  []*recipientMessage0
}

// recipientMessage0 represents a COSE_recipient structure without sub recipients to encode and decode.
type recipientMessage0 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
}

func (em *recipientMessage0) toEnc(context string, external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Enc_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-encrypt-and-decrypt-
	return key.MarshalCBOR([]any{
		context,      // context
		em.Protected, // body_protected
		external_aad, // external_aad
	})
}
