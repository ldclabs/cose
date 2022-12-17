// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Encryptor is the encrypting and decrypting interface for content encryption.
// It is used in COSE_Encrypt and COSE_Encrypt0.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#section-8.3
type Encryptor interface {
	// Encrypt encrypts a plaintext with the given nonce and additional data.
	// It returns the ciphertext or error.
	Encrypt(nonce, plaintext, additionalData []byte) (ciphertext []byte, err error)

	// Decrypt decrypts a ciphertext with the given nonce and additional data.
	// It returns the corresponding plaintext or error.
	Decrypt(nonce, ciphertext, additionalData []byte) (plaintext []byte, err error)

	// NonceSize returns the size of the nonce for encrypting and decrypting.
	NonceSize() int

	// Key returns the symmetric key in Encryptor.
	// If the "key_ops" field is present, it MUST include "encrypt" 3 when encrypting an plaintext.
	// If the "key_ops" field is present, it MUST include "decrypt" 4 when decrypting an ciphertext.
	Key() Key
}
