// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/go/key"
)

// Encrypt0Message represents a COSE_Encrypt0 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted
type Encrypt0Message struct {
	Protected   Headers
	Unprotected Headers
	// Plaintext should be set for encrypting
	Plaintext []byte
	// Ciphertext will be set after encrypting
	// or should be set for decrypting when DetachedCiphertext is true.
	Ciphertext []byte
	// If set to true, Ciphertext will not be encode into CBOR bytes.
	// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure
	DetachedCiphertext bool

	em    *encrypt0Message
	toEnc []byte
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
func (e *Encrypt0Message) Encrypt(encryptor key.Encryptor, externalData []byte) error {
	if e.Protected == nil {
		e.Protected = Headers{}

		if alg := encryptor.Key().Alg(); alg != key.AlgReserved {
			e.Protected[HeaderLabelAlgorithm] = alg
		}
	}

	if e.Unprotected == nil {
		e.Unprotected = Headers{}

		if kid := encryptor.Key().Kid(); len(kid) > 0 {
			e.Unprotected[HeaderLabelKeyID] = kid
		}
	}

	iv, err := e.Unprotected.GetBytes(HeaderLabelIV)
	if err != nil {
		return err
	}

	if len(iv) == 0 {
		iv := key.GetRandomBytes(uint16(encryptor.NonceSize()))
		e.Unprotected[HeaderLabelIV] = iv
	}

	em := &encrypt0Message{
		Protected:   []byte{},
		Unprotected: e.Unprotected,
	}

	if len(e.Protected) > 0 {
		em.Protected, err = key.MarshalCBOR(e.Protected)
		if err != nil {
			return err
		}
	}

	e.toEnc, err = em.toEnc(externalData)
	if err != nil {
		return err
	}

	if e.Ciphertext, err = encryptor.Encrypt(iv, e.Plaintext, e.toEnc); err == nil {
		e.em = em

		if !e.DetachedCiphertext {
			em.Ciphertext = e.Ciphertext
		}
	}
	return err
}

// Decrypt decrypts a COSE_Encrypt0 message with a Encryptor.
// It should call `Encrypt0Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used in Encrypt0Message.Encrypt.
func (e *Encrypt0Message) Decrypt(encryptor key.Encryptor, externalData []byte) error {
	if e.em == nil || e.Ciphertext == nil {
		return errors.New("cose/go/cose: Encrypt0Message.Decrypt: should call Encrypt0Message.UnmarshalCBOR")
	}

	var err error
	e.toEnc, err = e.em.toEnc(externalData)
	if err != nil {
		return err
	}

	iv, err := e.Unprotected.GetBytes(HeaderLabelIV)
	if err != nil {
		return err
	}

	e.Plaintext, err = encryptor.Decrypt(iv, e.Ciphertext, e.toEnc)
	return err
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
func (e *Encrypt0Message) MarshalCBOR() ([]byte, error) {
	if e.em == nil || e.Ciphertext == nil {
		return nil, errors.New("cose/go/cose: Encrypt0Message.MarshalCBOR: should call Encrypt0Message.Encrypt")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSEEncrypt0,
		Content: e.em,
	})
}

// mac0MessagePrefix represents the fixed prefix of COSE_Encrypt0_Tagged.
var encrypt0MessagePrefix = []byte{
	0xd0, // #6.16
	0x83, // array of length 3
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Mac0Message.
func (e *Encrypt0Message) UnmarshalCBOR(data []byte) error {
	if e == nil {
		return errors.New("cose/go/cose: Encrypt0Message.UnmarshalCBOR: nil Encrypt0Message")
	}
	// support untagged message
	if bytes.HasPrefix(data, encrypt0MessagePrefix) {
		data = data[1:]
	}

	em := &encrypt0Message{}
	if err := key.UnmarshalCBOR(data, em); err != nil {
		return err
	}

	protected := Headers{}
	if len(em.Protected) > 0 {
		if err := key.UnmarshalCBOR(em.Protected, &protected); err != nil {
			return err
		}
	}

	e.Protected = protected
	e.Unprotected = em.Unprotected
	e.DetachedCiphertext = len(em.Ciphertext) == 0
	if !e.DetachedCiphertext {
		e.Ciphertext = em.Ciphertext
	}

	e.em = em
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (e *Encrypt0Message) Bytesify() []byte {
	b, _ := e.MarshalCBOR()
	return b
}
