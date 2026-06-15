// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"errors"
	"fmt"

	"github.com/ldclabs/cose/iana"
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

	recipient.context = "Rec_Recipient"
	m.recipients = append(m.recipients, recipient)
	return nil
}

func (m *Recipient) Recipients() []*Recipient {
	return m.recipients
}

// recipient (content key distribution) algorithm classes, RFC 9052 §8.5.
const (
	recipientClassOther = iota
	recipientClassDirect
	recipientClassKeyWrap
	recipientClassKeyTransport
	recipientClassDirectKeyAgreement
	recipientClassKeyAgreementKeyWrap
)

// recipientClass maps a registered recipient algorithm to its §8.5 class.
func recipientClass(alg int) int {
	switch alg {
	case iana.AlgorithmDirect,
		iana.AlgorithmDirect_HKDF_SHA_256, iana.AlgorithmDirect_HKDF_SHA_512,
		iana.AlgorithmDirect_HKDF_AES_128, iana.AlgorithmDirect_HKDF_AES_256:
		return recipientClassDirect

	case iana.AlgorithmA128KW, iana.AlgorithmA192KW, iana.AlgorithmA256KW:
		return recipientClassKeyWrap

	case iana.AlgorithmRSAES_OAEP_SHA_512, iana.AlgorithmRSAES_OAEP_SHA_256,
		iana.AlgorithmRSAES_OAEP_RFC_8017_default:
		return recipientClassKeyTransport

	case iana.AlgorithmECDH_ES_HKDF_256, iana.AlgorithmECDH_ES_HKDF_512,
		iana.AlgorithmECDH_SS_HKDF_256, iana.AlgorithmECDH_SS_HKDF_512:
		return recipientClassDirectKeyAgreement

	case iana.AlgorithmECDH_ES_A128KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A256KW,
		iana.AlgorithmECDH_SS_A128KW, iana.AlgorithmECDH_SS_A192KW, iana.AlgorithmECDH_SS_A256KW:
		return recipientClassKeyAgreementKeyWrap

	default:
		return recipientClassOther
	}
}

// Validate checks the recipient layer against the structural rules in
// RFC 9052 §8.5 for the recipient (content key distribution) algorithm.
//
// It is an opt-in check: the decoder and marshaler treat Recipient as a
// generic structural container (recipient cryptography is delegated to the
// application), so call Validate explicitly when strict conformance to a
// specific recipient algorithm class is desired. Nested recipients are
// validated recursively.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#section-8.5.
func (m *Recipient) Validate() error {
	if m == nil {
		return errors.New("cose/cose: Recipient.Validate: nil Recipient")
	}

	// §8.5: "The 'alg' header parameter MUST be present." The recipient
	// algorithm may be carried in either the protected or unprotected bucket.
	hasAlg := m.Protected.Has(iana.HeaderParameterAlg) || m.Unprotected.Has(iana.HeaderParameterAlg)
	if !hasAlg {
		return errors.New(`cose/cose: Recipient.Validate: missing "alg" header parameter`)
	}

	// Only integer-registered algorithms have a known §8.5 class; private
	// text-string algorithms are accepted as long as "alg" is present.
	var alg int
	if m.Protected.Has(iana.HeaderParameterAlg) {
		alg, _ = m.Protected.GetInt(iana.HeaderParameterAlg)
	} else {
		alg, _ = m.Unprotected.GetInt(iana.HeaderParameterAlg)
	}

	switch recipientClass(alg) {
	case recipientClassDirect, recipientClassDirectKeyAgreement:
		// §8.5.1 / §8.5.4: the encrypted-key (ciphertext) field MUST be a
		// zero-length byte string and there MUST be no nested recipients.
		if len(m.Ciphertext) != 0 {
			return fmt.Errorf("cose/cose: Recipient.Validate: ciphertext MUST be empty for direct algorithm %d", alg)
		}
		if len(m.recipients) != 0 {
			return fmt.Errorf("cose/cose: Recipient.Validate: recipients MUST be absent for direct algorithm %d", alg)
		}

	case recipientClassKeyWrap, recipientClassKeyTransport:
		// §8.5.2 / §8.5.3: the protected bucket MUST be a zero-length byte string.
		if len(m.Protected) != 0 {
			return fmt.Errorf("cose/cose: Recipient.Validate: protected header MUST be empty for algorithm %d", alg)
		}
	}

	for _, r := range m.recipients {
		if err := r.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// MarshalCBOR implements the CBOR Marshaler interface for Recipient.
func (m *Recipient) MarshalCBOR() ([]byte, error) {
	mm0 := &recipientMessage0{
		Unprotected: m.Unprotected,
		Ciphertext:  m.Ciphertext,
	}
	var err error
	if mm0.Protected, err = m.Protected.Bytes(); err != nil {
		return nil, err
	}
	if mm0.Unprotected == nil {
		mm0.Unprotected = Headers{}
	}

	if len(m.recipients) == 0 {
		return key.MarshalCBOR(mm0)
	}

	mm := &recipientMessage{
		Protected:   mm0.Protected,
		Unprotected: mm0.Unprotected,
		Ciphertext:  mm0.Ciphertext,
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

	var err error
	switch data[0] {
	case 0x83: // array(3)
		mm := &recipientMessage0{}
		if err = key.UnmarshalCBOR(data, mm); err != nil {
			return err
		}

		if m.Protected, err = HeadersFromBytes(mm.Protected); err != nil {
			return err
		}

		m.Unprotected = mm.Unprotected
		if err = checkHeaders(m.Protected, m.Unprotected); err != nil {
			return err
		}
		m.Ciphertext = mm.Ciphertext

	case 0x84:
		mm := &recipientMessage{}
		if err = key.UnmarshalCBOR(data, mm); err != nil {
			return err
		}
		if len(mm.Recipients) == 0 {
			return errors.New("cose/cose: Recipient.UnmarshalCBOR: no recipients")
		}
		for _, r := range mm.Recipients {
			if r == nil {
				return errors.New("cose/cose: Recipient.UnmarshalCBOR: nil Recipient")
			}
			if len(r.recipients) > 0 {
				return errors.New("cose/cose: Recipient.UnmarshalCBOR: should not have nested recipients")
			}
		}

		if m.Protected, err = HeadersFromBytes(mm.Protected); err != nil {
			return err
		}

		m.Unprotected = mm.Unprotected
		if err = checkHeaders(m.Protected, m.Unprotected); err != nil {
			return err
		}
		m.Ciphertext = mm.Ciphertext
		m.recipients = mm.Recipients

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
