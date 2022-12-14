// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Encryptor is the encrypting and decrypting interface for content encryption.
// It is used in COSE_Encrypt and COSE_Encrypt0.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#section-8.3
type Encryptor interface {
	// Encrypt encrypts the given plaintext with the given additional data.
	// It returns the concatenation of the primary's identifier and the ciphertext.
	Encrypt(plaintext, additionalData []byte) ([]byte, error)

	// Decrypt decrypts the given ciphertext and authenticates it with the given
	// additional data. It returns the corresponding plaintext if the
	// ciphertext is authenticated.
	Decrypt(ciphertext, additionalData []byte) ([]byte, error)

	// Key returns the symmetric key in Encryptor.
	// If the "key_ops" field is present, it MUST include "encrypt" 3 when encrypting an plaintext.
	// If the "key_ops" field is present, it MUST include "decrypt" 4 when decrypting an ciphertext.
	Key() Key
}
