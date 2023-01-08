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

// EncryptMessage represents a COSE_Encrypt object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted.
type EncryptMessage[T any] struct {
	// protected header parameters: iana.HeaderParameterAlg, iana.HeaderParameterCrit.
	Protected Headers
	// Other header parameters.
	Unprotected Headers
	// If payload is []byte or cbor.RawMessage,
	// it will not be encoded/decoded by key.MarshalCBOR/key.UnmarshalCBOR.
	Payload T

	recipients []*Recipient
	mm         *encryptMessage
	toEnc      []byte
}

// DecryptEncryptMessage decrypts and decodes a COSE_Encrypt object with a Encryptor and returns a *EncryptMessage.
// `externalData` should be the same as the one used when encrypting.
func DecryptEncryptMessage[T any](encryptor key.Encryptor, coseData, externalData []byte) (*EncryptMessage[T], error) {
	m := &EncryptMessage[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Decrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// EncryptAndEncode encrypts and encodes a COSE_Encrypt object with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data.
func (m *EncryptMessage[T]) EncryptAndEncode(encryptor key.Encryptor, externalData []byte) ([]byte, error) {
	if err := m.Encrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// AddRecipient add a COSE Recipient to the COSE_Encrypt object.
func (m *EncryptMessage[T]) AddRecipient(recipient *Recipient) error {
	if recipient == nil {
		return errors.New("cose/cose: EncryptMessage.AddRecipient: nil recipient")
	}

	if err := recipient.init(); err != nil {
		return err
	}

	if recipient.context != "" {
		return fmt.Errorf("cose/cose: MacMessage.AddRecipient: should not have %q context",
			recipient.context)
	}
	recipient.context = "Enc_Recipient"
	m.recipients = append(m.recipients, recipient)
	return nil
}

// Recipients returns recipients in the COSE_Encrypt object
func (m *EncryptMessage[T]) Recipients() []*Recipient {
	return m.recipients
}

// Encrypt encrypt a COSE_Encrypt object with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data.
func (m *EncryptMessage[T]) Encrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := encryptor.Key().Alg(); alg != iana.AlgorithmReserved {
			m.Protected[iana.HeaderParameterAlg] = alg
		}
	} else if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ := m.Protected.GetInt(iana.HeaderParameterAlg)
		if alg != int(encryptor.Key().Alg()) {
			return fmt.Errorf("cose/cose: EncryptMessage.Encrypt: encryptor'alg mismatch, expected %d, got %d",
				alg, encryptor.Key().Alg())
		}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := encryptor.Key().Kid(); len(kid) > 0 {
			m.Unprotected[iana.HeaderParameterKid] = kid
		}
	}

	iv, err := m.Unprotected.GetBytes(iana.HeaderParameterIV)
	if err != nil {
		return err
	}

	if len(iv) == 0 {
		iv = key.GetRandomBytes(uint16(encryptor.NonceSize()))
		m.Unprotected[iana.HeaderParameterIV] = iv
	}

	mm := &encryptMessage{
		Protected:   []byte{},
		Unprotected: m.Unprotected,
	}

	if len(m.Protected) > 0 {
		mm.Protected, err = key.MarshalCBOR(m.Protected)
		if err != nil {
			return err
		}
	}

	var plaintext []byte
	switch v := any(m.Payload).(type) {
	case []byte:
		plaintext = v
	case cbor.RawMessage:
		plaintext = v
	default:
		plaintext, err = key.MarshalCBOR(m.Payload)
		if err != nil {
			return err
		}
	}

	m.toEnc, err = mm.toEnc(externalData)
	if err != nil {
		return err
	}

	mm.Ciphertext, err = encryptor.Encrypt(iv, plaintext, m.toEnc)
	if err != nil {
		return err
	}

	m.mm = mm
	return nil
}

// Decrypt decrypts a COSE_Encrypt object with a Encryptor.
// It should call `EncryptMessage.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used when encrypting.
func (m *EncryptMessage[T]) Decrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.mm == nil || m.mm.Ciphertext == nil {
		return errors.New("cose/cose: EncryptMessage.Decrypt: should call EncryptMessage.UnmarshalCBOR")
	}

	if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ := m.Protected.GetInt(iana.HeaderParameterAlg)
		if alg != int(encryptor.Key().Alg()) {
			return fmt.Errorf("cose/cose: EncryptMessage.Decrypt: encryptor'alg mismatch, expected %d, got %d",
				alg, encryptor.Key().Alg())
		}
	}

	var err error
	m.toEnc, err = m.mm.toEnc(externalData)
	if err != nil {
		return err
	}

	iv, err := m.Unprotected.GetBytes(iana.HeaderParameterIV)
	if err != nil {
		return err
	}

	plaintext, err := encryptor.Decrypt(iv, m.mm.Ciphertext, m.toEnc)
	if err != nil {
		return err
	}
	if len(plaintext) > 0 {
		switch any(m.Payload).(type) {
		case []byte:
			m.Payload = any(plaintext).(T)
		case cbor.RawMessage:
			m.Payload = any(cbor.RawMessage(plaintext)).(T)
		default:
			if err := key.UnmarshalCBOR(plaintext, &m.Payload); err != nil {
				return err
			}
		}
	}

	return nil
}

// encryptMessage represents a COSE_Encrypt structure to encode and decode.
type encryptMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
	Recipients  []*Recipient
}

func (mm *encryptMessage) toEnc(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}

	// Enc_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-encrypt-and-decrypt-
	return key.MarshalCBOR([]any{
		"Encrypt",    // context
		mm.Protected, // body_protected
		external_aad, // external_aad
	})
}

// MarshalCBOR implements the CBOR Marshaler interface for EncryptMessage.
// It should call `EncryptMessage.Encrypt` before calling this method.
func (m *EncryptMessage[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Ciphertext == nil {
		return nil, errors.New("cose/cose: EncryptMessage.MarshalCBOR: should call EncryptMessage.Encrypt")
	}

	if len(m.recipients) == 0 {
		return nil, errors.New("cose/cose: EncryptMessage.MarshalCBOR: no recipients")
	}

	m.mm.Recipients = m.recipients
	return key.MarshalCBOR(cbor.Tag{
		Number:  iana.CBORTagCOSEEncrypt,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for EncryptMessage.
func (m *EncryptMessage[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: EncryptMessage.UnmarshalCBOR: nil EncryptMessage")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	// support untagged message
	if bytes.HasPrefix(data, encryptMessagePrefix) {
		data = data[1:]
	}

	mm := &encryptMessage{}
	if err := key.UnmarshalCBOR(data, mm); err != nil {
		return err
	}

	if len(mm.Recipients) == 0 {
		return errors.New("cose/cose: EncryptMessage.UnmarshalCBOR: no recipients")
	}
	for _, r := range mm.Recipients {
		if r == nil {
			return errors.New("cose/cose: EncryptMessage.UnmarshalCBOR: nil recipient")
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
	m.recipients = mm.Recipients
	m.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *EncryptMessage[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}
