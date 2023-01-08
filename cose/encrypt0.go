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

// Encrypt0Message represents a COSE_Encrypt0 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted.
type Encrypt0Message[T any] struct {
	// protected header parameters: iana.HeaderParameterAlg, iana.HeaderParameterCrit.
	Protected Headers
	// Other header parameters.
	Unprotected Headers
	// If payload is []byte or cbor.RawMessage,
	// it will not be encoded/decoded by key.MarshalCBOR/key.UnmarshalCBOR.
	Payload T

	mm    *encrypt0Message
	toEnc []byte
}

// DecryptEncrypt0Message decrypts and decodes a COSE_Encrypt0 object with a Encryptor and returns a *Encrypt0Message.
// `externalData` should be the same as the one used when encrypting.
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

// EncryptAndEncode encrypts and encodes a COSE_Encrypt0 object with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Encrypt0Message[T]) EncryptAndEncode(encryptor key.Encryptor, externalData []byte) ([]byte, error) {
	if err := m.Encrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// Encrypt encrypt a COSE_Encrypt0 object with a Encryptor.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Encrypt0Message[T]) Encrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := encryptor.Key().Alg(); alg != iana.AlgorithmReserved {
			m.Protected[iana.HeaderParameterAlg] = alg
		}
	} else if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ := m.Protected.GetInt(iana.HeaderParameterAlg)
		if alg != int(encryptor.Key().Alg()) {
			return fmt.Errorf("cose/cose: Encrypt0Message.Encrypt: encryptor'alg mismatch, expected %d, got %d",
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
	partialIV, err := m.Unprotected.GetBytes(iana.HeaderParameterPartialIV)
	if err != nil {
		return err
	}
	ivSize := encryptor.NonceSize()
	if len(partialIV) > 0 {
		if len(iv) > 0 {
			return errors.New("cose/cose: Encrypt0Message.Encrypt: both iv and partial iv are present")
		}
		if len(partialIV) >= ivSize {
			return errors.New("cose/cose: Encrypt0Message.Encrypt: partial iv is too long")
		}

		baseIV, err := encryptor.Key().GetBytes(iana.KeyParameterBaseIV)
		if err != nil {
			return err
		}

		if len(baseIV) == 0 {
			return errors.New("cose/cose: Encrypt0Message.Encrypt: base iv is missing")
		}

		iv = xorIV(baseIV, partialIV, ivSize)
	}
	if len(iv) == 0 {
		iv = key.GetRandomBytes(uint16(ivSize))
		m.Unprotected[iana.HeaderParameterIV] = iv
	}

	mm := &encrypt0Message{
		Unprotected: m.Unprotected,
	}
	if mm.Protected, err = m.Protected.Bytes(); err != nil {
		return err
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

// Decrypt decrypts a COSE_Encrypt0 object with a Encryptor.
// It should call `Encrypt0Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used when encrypting.
func (m *Encrypt0Message[T]) Decrypt(encryptor key.Encryptor, externalData []byte) error {
	if m.mm == nil || m.mm.Ciphertext == nil {
		return errors.New("cose/cose: Encrypt0Message.Decrypt: should call Encrypt0Message.UnmarshalCBOR")
	}

	if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ := m.Protected.GetInt(iana.HeaderParameterAlg)
		if alg != int(encryptor.Key().Alg()) {
			return fmt.Errorf("cose/cose: Encrypt0Message.Decrypt: encryptor'alg mismatch, expected %d, got %d",
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
	partialIV, err := m.Unprotected.GetBytes(iana.HeaderParameterPartialIV)
	if err != nil {
		return err
	}
	ivSize := encryptor.NonceSize()
	if len(partialIV) > 0 {
		if len(iv) > 0 {
			return errors.New("cose/cose: Encrypt0Message.Decrypt: both iv and partial iv are present")
		}

		if len(partialIV) >= ivSize {
			return errors.New("cose/cose: Encrypt0Message.Decrypt: partial iv is too long")
		}

		baseIV, err := encryptor.Key().GetBytes(iana.KeyParameterBaseIV)
		if err != nil {
			return err
		}

		if len(baseIV) == 0 {
			return errors.New("cose/cose: Encrypt0Message.Decrypt: base iv is missing")
		}

		iv = xorIV(baseIV, partialIV, ivSize)
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

// encrypt0Message represents a COSE_Encrypt0 structure to encode and decode.
type encrypt0Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Ciphertext  []byte // can be nil
}

func (mm *encrypt0Message) toEnc(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// Enc_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-encrypt-and-decrypt-
	return key.MarshalCBOR([]any{
		"Encrypt0",   // context
		mm.Protected, // body_protected
		external_aad, // external_aad
	})
}

// MarshalCBOR implements the CBOR Marshaler interface for Encrypt0Message.
// It should call `Encrypt0Message.Encrypt` before calling this method.
func (m *Encrypt0Message[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Ciphertext == nil {
		return nil, errors.New("cose/cose: Encrypt0Message.MarshalCBOR: should call Encrypt0Message.Encrypt")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  iana.CBORTagCOSEEncrypt0,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Encrypt0Message.
func (m *Encrypt0Message[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: Encrypt0Message.UnmarshalCBOR: nil Encrypt0Message")
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

	var err error
	if m.Protected, err = HeadersFromBytes(mm.Protected); err != nil {
		return err
	}

	m.Unprotected = mm.Unprotected
	m.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *Encrypt0Message[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

// https://datatracker.ietf.org/doc/html/rfc9052#name-common-cose-header-paramete
func xorIV(contextIV, partialIV []byte, size int) []byte {
	iv := make([]byte, size)
	copy(iv[size-len(partialIV):], partialIV)
	for i := range iv {
		if i >= len(contextIV) {
			break
		}
		iv[i] ^= contextIV[i]
	}
	return iv
}
