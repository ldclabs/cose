// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
)

// Encrypt0Message represents a COSE_Encrypt0 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted
type Encrypt0Message[T any] struct {
	Protected   Headers
	Unprotected Headers
	Payload     T // Payload should be set for encrypting
	// Ciphertext will be set after encrypting
	// or should be set for decrypting when DetachedCiphertext is true.
	Ciphertext []byte
	// If set to true, Ciphertext will not be encode into CBOR bytes.
	// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure
	DetachedCiphertext bool

	mm    *encrypt0Message
	toEnc []byte
}

// DecryptEncrypt0Message decrypts and decodes a COSE_Encrypt0 message with a Encryptor and returns a *Encrypt0Message.
// `externalData` should be the same as the one used in `Encrypt0Message.EncryptAndEncode`.
func DecryptEncrypt0Message[T any](encryptor key.Encryptor, coseData, externalData []byte) (*Encrypt0Message[T], error) {
	m := &Encrypt0Message[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Decrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// EncryptAndEncode encrypts and encodes a COSE_Encrypt0 message with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Encrypt0Message[T]) EncryptAndEncode(encryptor key.Encryptor, externalData []byte) ([]byte, error) {
	if err := m.Encrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// encrypt0Message represents a COSE_Encrypt0 structure to encode and decode.
type encrypt0Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
}

// Encrypt encrypt a COSE_Encrypt0 message with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Encrypt0Message[T]) Encrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := encryptor.Key().Alg(); alg != key.AlgReserved {
			m.Protected[HeaderLabelAlgorithm] = alg
		}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := encryptor.Key().Kid(); len(kid) > 0 {
			m.Unprotected[HeaderLabelKeyID] = kid
		}
	}

	iv, err := m.Unprotected.GetBytes(HeaderLabelIV)
	if err != nil {
		return err
	}

	if len(iv) == 0 {
		iv := key.GetRandomBytes(uint16(encryptor.NonceSize()))
		m.Unprotected[HeaderLabelIV] = iv
	}

	mm := &encrypt0Message{
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

	if m.Ciphertext, err = encryptor.Encrypt(iv, plaintext, m.toEnc); err == nil {
		m.mm = mm

		if !m.DetachedCiphertext {
			mm.Ciphertext = m.Ciphertext
		}
	}
	return err
}

// Decrypt decrypts a COSE_Encrypt0 message with a Encryptor.
// It should call `Encrypt0Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used in Encrypt0Message.Encrypt.
func (m *Encrypt0Message[T]) Decrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.mm == nil || m.Ciphertext == nil {
		return errors.New("cose/go/cose: Encrypt0Message.Decrypt: should call Encrypt0Message.UnmarshalCBOR")
	}

	var err error
	m.toEnc, err = m.mm.toEnc(externalData)
	if err != nil {
		return err
	}

	iv, err := m.Unprotected.GetBytes(HeaderLabelIV)
	if err != nil {
		return err
	}

	plaintext, err := encryptor.Decrypt(iv, m.Ciphertext, m.toEnc)
	if err != nil {
		return err
	}
	if len(plaintext) > 0 {
		switch any(m.Payload).(type) {
		case []byte:
			m.Payload = any(plaintext).(T)
		case cbor.RawMessage:
			m.Payload = any(plaintext).(T)
		default:
			if err := key.UnmarshalCBOR(plaintext, &m.Payload); err != nil {
				return err
			}
		}
	}

	return nil
}

func (em *encrypt0Message) toEnc(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Enc_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-encrypt-and-decrypt-
	return key.MarshalCBOR([]any{
		"Encrypt0",   // context
		em.Protected, // body_protected
		external_aad, // external_aad
	})
}

// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const cborTagCOSEEncrypt0 = 16

// MarshalCBOR implements the CBOR Marshaler interface for Encrypt0Message.
// It should call `Encrypt0Message.Encrypt` before calling this method.
func (m *Encrypt0Message[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.Ciphertext == nil {
		return nil, errors.New("cose/go/cose: Encrypt0Message.MarshalCBOR: should call Encrypt0Message.Encrypt")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSEEncrypt0,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Mac0Message.
func (m *Encrypt0Message[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/go/cose: Encrypt0Message.UnmarshalCBOR: nil Encrypt0Message")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	// support untagged message
	if bytes.HasPrefix(data, encrypt0MessagePrefix) {
		data = data[1:]
	}

	mm := &encrypt0Message{}
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
	m.DetachedCiphertext = len(mm.Ciphertext) == 0
	if !m.DetachedCiphertext {
		m.Ciphertext = mm.Ciphertext
	}

	m.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *Encrypt0Message[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}
