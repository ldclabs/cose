// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/ldclabs/cose/key"
)

// Detached content support, RFC 9052 §4.1, §5.1 and §6.1.
//
// When content is "detached" it is transported separately from the COSE
// structure: the payload / ciphertext field is encoded as a nil CBOR object,
// while the cryptographic computation still uses the full payload. These
// helpers make detached signing, MACing and encryption explicit so that the
// Sig_structure / MAC_structure use the real payload (not nil) and the caller
// supplies the detached content again at verification / decryption time.

// marshalPayload serializes a typed payload the same way the attached
// sign/compute/encrypt paths do.
func marshalPayload[T any](payload T) ([]byte, error) {
	switch v := any(payload).(type) {
	case []byte:
		return v, nil
	case cbor.RawMessage:
		return v, nil
	default:
		return key.MarshalCBOR(payload)
	}
}

// --- COSE_Sign1 -------------------------------------------------------------

// SignDetached signs a COSE_Sign1 message over m.Payload but encodes the
// payload field as nil (detached content). `externalData` can be nil.
func (m *Sign1Message[T]) SignDetached(signer key.Signer, externalData []byte) error {
	if err := m.WithSign(signer, externalData); err != nil {
		return err
	}
	m.detached = true
	return nil
}

// SignDetachedAndEncode signs and encodes a detached-payload COSE_Sign1 message.
func (m *Sign1Message[T]) SignDetachedAndEncode(signer key.Signer, externalData []byte) ([]byte, error) {
	if err := m.SignDetached(signer, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// VerifyDetached verifies a detached-payload COSE_Sign1 message against the
// externally supplied payload. Call after Sign1Message.UnmarshalCBOR.
func (m *Sign1Message[T]) VerifyDetached(verifier key.Verifier, payload T, externalData []byte) error {
	if m.mm == nil || m.mm.Signature == nil {
		return errors.New("cose/cose: Sign1Message.VerifyDetached: should call Sign1Message.UnmarshalCBOR")
	}
	pb, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	m.Payload = payload
	m.mm.Payload = pb
	m.detached = true
	return m.Verify(verifier, externalData)
}

// VerifySign1MessageDetached verifies and decodes a detached-payload COSE_Sign1
// message with a Verifier and the externally supplied payload.
func VerifySign1MessageDetached[T any](verifier key.Verifier, coseData []byte, payload T, externalData []byte) (*Sign1Message[T], error) {
	m := &Sign1Message[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.VerifyDetached(verifier, payload, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// --- COSE_Sign --------------------------------------------------------------

// SignDetached signs a COSE_Sign message over m.Payload but encodes the payload
// field as nil (detached content). `externalData` can be nil.
func (m *SignMessage[T]) SignDetached(signers key.Signers, externalData []byte) error {
	if err := m.WithSign(signers, externalData); err != nil {
		return err
	}
	m.detached = true
	return nil
}

// SignDetachedAndEncode signs and encodes a detached-payload COSE_Sign message.
func (m *SignMessage[T]) SignDetachedAndEncode(signers key.Signers, externalData []byte) ([]byte, error) {
	if err := m.SignDetached(signers, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// VerifyDetached verifies a detached-payload COSE_Sign message against the
// externally supplied payload. Call after SignMessage.UnmarshalCBOR.
func (m *SignMessage[T]) VerifyDetached(verifiers key.Verifiers, payload T, externalData []byte) error {
	if m.mm == nil || m.mm.Signatures == nil {
		return errors.New("cose/cose: SignMessage.VerifyDetached: should call SignMessage.UnmarshalCBOR")
	}
	pb, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	m.Payload = payload
	m.mm.Payload = pb
	m.detached = true
	return m.Verify(verifiers, externalData)
}

// VerifySignMessageDetached verifies and decodes a detached-payload COSE_Sign
// message with some Verifiers and the externally supplied payload.
func VerifySignMessageDetached[T any](verifiers key.Verifiers, coseData []byte, payload T, externalData []byte) (*SignMessage[T], error) {
	m := &SignMessage[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.VerifyDetached(verifiers, payload, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// --- COSE_Mac0 --------------------------------------------------------------

// ComputeDetached computes a COSE_Mac0 tag over m.Payload but encodes the
// payload field as nil (detached content). `externalData` can be nil.
func (m *Mac0Message[T]) ComputeDetached(macer key.MACer, externalData []byte) error {
	if err := m.Compute(macer, externalData); err != nil {
		return err
	}
	m.detached = true
	return nil
}

// ComputeDetachedAndEncode computes and encodes a detached-payload COSE_Mac0 object.
func (m *Mac0Message[T]) ComputeDetachedAndEncode(macer key.MACer, externalData []byte) ([]byte, error) {
	if err := m.ComputeDetached(macer, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// VerifyDetached verifies a detached-payload COSE_Mac0 object against the
// externally supplied payload. Call after Mac0Message.UnmarshalCBOR.
func (m *Mac0Message[T]) VerifyDetached(macer key.MACer, payload T, externalData []byte) error {
	if m.mm == nil || m.mm.Tag == nil {
		return errors.New("cose/cose: Mac0Message.VerifyDetached: should call Mac0Message.UnmarshalCBOR")
	}
	pb, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	m.Payload = payload
	m.mm.Payload = pb
	m.detached = true
	return m.Verify(macer, externalData)
}

// VerifyMac0MessageDetached verifies and decodes a detached-payload COSE_Mac0
// object with a MACer and the externally supplied payload.
func VerifyMac0MessageDetached[T any](macer key.MACer, coseData []byte, payload T, externalData []byte) (*Mac0Message[T], error) {
	m := &Mac0Message[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.VerifyDetached(macer, payload, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// --- COSE_Mac ---------------------------------------------------------------

// ComputeDetached computes a COSE_Mac tag over m.Payload but encodes the
// payload field as nil (detached content). Recipients must still be added
// before encoding. `externalData` can be nil.
func (m *MacMessage[T]) ComputeDetached(macer key.MACer, externalData []byte) error {
	if err := m.Compute(macer, externalData); err != nil {
		return err
	}
	m.detached = true
	return nil
}

// VerifyDetached verifies a detached-payload COSE_Mac object against the
// externally supplied payload. Call after MacMessage.UnmarshalCBOR.
func (m *MacMessage[T]) VerifyDetached(macer key.MACer, payload T, externalData []byte) error {
	if m.mm == nil || m.mm.Tag == nil {
		return errors.New("cose/cose: MacMessage.VerifyDetached: should call MacMessage.UnmarshalCBOR")
	}
	pb, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	m.Payload = payload
	m.mm.Payload = pb
	m.detached = true
	return m.Verify(macer, externalData)
}

// VerifyMacMessageDetached verifies and decodes a detached-payload COSE_Mac
// object with a MACer and the externally supplied payload.
func VerifyMacMessageDetached[T any](macer key.MACer, coseData []byte, payload T, externalData []byte) (*MacMessage[T], error) {
	m := &MacMessage[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.VerifyDetached(macer, payload, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// --- COSE_Encrypt0 ----------------------------------------------------------

// EncryptDetached encrypts a COSE_Encrypt0 object and returns the ciphertext
// for separate transport; the encoded message (MarshalCBOR) carries a nil
// ciphertext. `externalData` can be nil.
func (m *Encrypt0Message[T]) EncryptDetached(encryptor key.Encryptor, externalData []byte) (ciphertext []byte, err error) {
	if err = m.Encrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	m.detached = true
	return m.mm.Ciphertext, nil
}

// DecryptDetached decrypts a detached-ciphertext COSE_Encrypt0 object using the
// externally supplied ciphertext. Call after Encrypt0Message.UnmarshalCBOR.
func (m *Encrypt0Message[T]) DecryptDetached(encryptor key.Encryptor, ciphertext, externalData []byte) error {
	if m.mm == nil {
		return errors.New("cose/cose: Encrypt0Message.DecryptDetached: should call Encrypt0Message.UnmarshalCBOR")
	}
	if len(ciphertext) == 0 {
		return errors.New("cose/cose: Encrypt0Message.DecryptDetached: empty ciphertext")
	}
	m.mm.Ciphertext = ciphertext
	m.detached = true
	return m.Decrypt(encryptor, externalData)
}

// DecryptEncrypt0MessageDetached decrypts and decodes a detached-ciphertext
// COSE_Encrypt0 object with an Encryptor and the externally supplied ciphertext.
func DecryptEncrypt0MessageDetached[T any](encryptor key.Encryptor, coseData, ciphertext, externalData []byte) (*Encrypt0Message[T], error) {
	m := &Encrypt0Message[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.DecryptDetached(encryptor, ciphertext, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// --- COSE_Encrypt -----------------------------------------------------------

// EncryptDetached encrypts a COSE_Encrypt object and returns the ciphertext for
// separate transport; the encoded message (MarshalCBOR) carries a nil
// ciphertext. Recipients must still be added before encoding. `externalData`
// can be nil.
func (m *EncryptMessage[T]) EncryptDetached(encryptor key.Encryptor, externalData []byte) (ciphertext []byte, err error) {
	if err = m.Encrypt(encryptor, externalData); err != nil {
		return nil, err
	}
	m.detached = true
	return m.mm.Ciphertext, nil
}

// DecryptDetached decrypts a detached-ciphertext COSE_Encrypt object using the
// externally supplied ciphertext. Call after EncryptMessage.UnmarshalCBOR.
func (m *EncryptMessage[T]) DecryptDetached(encryptor key.Encryptor, ciphertext, externalData []byte) error {
	if m.mm == nil {
		return errors.New("cose/cose: EncryptMessage.DecryptDetached: should call EncryptMessage.UnmarshalCBOR")
	}
	if len(ciphertext) == 0 {
		return errors.New("cose/cose: EncryptMessage.DecryptDetached: empty ciphertext")
	}
	m.mm.Ciphertext = ciphertext
	m.detached = true
	return m.Decrypt(encryptor, externalData)
}

// DecryptEncryptMessageDetached decrypts and decodes a detached-ciphertext
// COSE_Encrypt object with an Encryptor and the externally supplied ciphertext.
func DecryptEncryptMessageDetached[T any](encryptor key.Encryptor, coseData, ciphertext, externalData []byte) (*EncryptMessage[T], error) {
	m := &EncryptMessage[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.DecryptDetached(encryptor, ciphertext, externalData); err != nil {
		return nil, err
	}
	return m, nil
}
