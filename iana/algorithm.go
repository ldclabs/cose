// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package iana registers COSE: https://www.iana.org/assignments/cose/cose.xhtml,
// CWT: https://www.iana.org/assignments/cwt/cwt.xhtml,
// and CBOR Tags: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml.
package iana

// IANA-registered COSE algorithms.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// as of 2022-12-19.
const (
	// RSASSA-PKCS1-v1_5 using SHA-1
	AlgorithmRS1 = -65535
	// WalnutDSA signature
	AlgorithmWalnutDSA = -260
	// RSASSA-PKCS1-v1_5 using SHA-512
	AlgorithmRS512 = -259
	// RSASSA-PKCS1-v1_5 using SHA-384
	AlgorithmRS384 = -258
	// RSASSA-PKCS1-v1_5 using SHA-256
	AlgorithmRS256 = -257
	// ECDSA using secp256k1 curve and SHA-256
	AlgorithmES256K = -47
	// HSS/LMS hash-based digital signature
	AlgorithmHSS_LMS = -46
	// SHAKE-256 512-bit Hash Value
	AlgorithmSHAKE256 = -45
	// SHA-2 512-bit Hash
	AlgorithmSHA_512 = -44
	// SHA-2 384-bit Hash
	AlgorithmSHA_384 = -43
	// RSAES-OAEP w/ SHA-512
	AlgorithmRSAES_OAEP_SHA_512 = -42
	// RSAES-OAEP w/ SHA-256
	AlgorithmRSAES_OAEP_SHA_256 = -41
	// RSAES-OAEP w/ SHA-1
	AlgorithmRSAES_OAEP_RFC_8017_default = -40
	// RSASSA-PSS w/ SHA-512
	AlgorithmPS512 = -39
	// RSASSA-PSS_SHA-384
	AlgorithmPS384 = -38
	// RSASSA-PSS w/ SHA-256
	AlgorithmPS256 = -37
	// ECDSA w/ SHA-512
	AlgorithmES512 = -36
	// ECDSA w/ SHA-384
	AlgorithmES384 = -35
	// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
	AlgorithmECDH_SS_A256KW = -34
	// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
	AlgorithmECDH_SS_A192KW = -33
	// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
	AlgorithmECDH_SS_A128KW = -32
	// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
	AlgorithmECDH_ES_A256KW = -31
	// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
	AlgorithmECDH_ES_A192KW = -30
	// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
	AlgorithmECDH_ES_A128KW = -29
	// ECDH SS w/ HKDF - generate key directly
	AlgorithmECDH_SS_HKDF_512 = -28
	// ECDH SS w/ HKDF - generate key directly
	AlgorithmECDH_SS_HKDF_256 = -27
	// ECDH ES w/ HKDF - generate key directly
	AlgorithmECDH_ES_HKDF_512 = -26
	// ECDH ES w/ HKDF - generate key directly
	AlgorithmECDH_ES_HKDF_256 = -25
	// SHAKE-128 256-bit Hash Value
	AlgorithmSHAKE128 = -18
	// SHA-2 512-bit Hash truncated to 256-bits
	AlgorithmSHA_512_256 = -17
	// SHA-2 256-bit Hash
	AlgorithmSHA_256 = -16
	// SHA-2 256-bit Hash truncated to 64-bits
	AlgorithmSHA_256_64 = -15
	// SHA-1 Hash
	AlgorithmSHA_1 = -14
	// Shared secret w/ AES-MAC 256-bit key
	AlgorithmDirect_HKDF_AES_256 = -13
	// Shared secret w/ AES-MAC 128-bit key
	AlgorithmDirect_HKDF_AES_128 = -12
	// Shared secret w/ HKDF and SHA-512
	AlgorithmDirect_HKDF_SHA_512 = -11
	// Shared secret w/ HKDF and SHA-256
	AlgorithmDirect_HKDF_SHA_256 = -10
	// EdDSA
	AlgorithmEdDSA = -8
	// ECDSA w/ SHA-256
	AlgorithmES256 = -7
	// Direct use of CEK
	AlgorithmDirect = -6
	// AES Key Wrap w/ 256-bit key
	AlgorithmA256KW = -5
	// AES Key Wrap w/ 192-bit key
	AlgorithmA192KW = -4
	// AES Key Wrap w/ 128-bit key
	AlgorithmA128KW = -3
	// Reserved
	AlgorithmReserved = 0
	// AES-GCM mode w/ 128-bit key, 128-bit tag
	AlgorithmA128GCM = 1
	// AES-GCM mode w/ 192-bit key, 128-bit tag
	AlgorithmA192GCM = 2
	// AES-GCM mode w/ 256-bit key, 128-bit tag
	AlgorithmA256GCM = 3
	// HMAC w/ SHA-256 truncated to 64 bits
	AlgorithmHMAC_256_64 = 4
	// HMAC w/ SHA-256
	AlgorithmHMAC_256_256 = 5
	// HMAC w/ SHA-384
	AlgorithmHMAC_384_384 = 6
	// HMAC w/ SHA-512
	AlgorithmHMAC_512_512 = 7
	// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
	AlgorithmAES_CCM_16_64_128 = 10
	// AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
	AlgorithmAES_CCM_16_64_256 = 11
	// AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
	AlgorithmAES_CCM_64_64_128 = 12
	// AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
	AlgorithmAES_CCM_64_64_256 = 13
	// AES-MAC 128-bit key, 64-bit tag
	AlgorithmAES_MAC_128_64 = 14
	// AES-MAC 256-bit key, 64-bit tag
	AlgorithmAES_MAC_256_64 = 15
	// ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
	AlgorithmChaCha20Poly1305 = 24
	// AES-MAC 128-bit key, 128-bit tag
	AlgorithmAES_MAC_128_128 = 25
	// AES-MAC 256-bit key, 128-bit tag
	AlgorithmAES_MAC_256_128 = 26
	// AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
	AlgorithmAES_CCM_16_128_128 = 30
	// AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
	AlgorithmAES_CCM_16_128_256 = 31
	// AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
	AlgorithmAES_CCM_64_128_128 = 32
	// AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
	AlgorithmAES_CCM_64_128_256 = 33
	// For doing IV generation for symmetric algorithms.
	AlgorithmIV_GENERATION = 34
)
