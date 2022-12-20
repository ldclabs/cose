// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package iana

// IANA-registered COSE common key parameters.
//
// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters>
// as of 2022-12-19.
const (
	// Reserved value.
	KeyParameterReserved = 0
	// Identification of the key type
	//
	// Associated value of type tstr / int
	KeyParameterKty = 1
	// Key identification value - match to kid in message
	//
	// Associated value of type bstr
	KeyParameterKid = 2
	// Key usage restriction to this algorithm
	//
	// Associated value of type tstr / int
	KeyParameterAlg = 3
	// Restrict set of permissible operations
	//
	// Associated value of type [+ (tstr / int)]
	KeyParameterKeyOps = 4
	// Base IV to be XORed with Partial IVs
	//
	// Associated value of type bstr
	KeyParameterBaseIV = 5
)

// IANA-registered COSE key types.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type
// as of 2022-12-19.
const (
	// This value is reserved
	KeyTypeReserved = 0
	// Octet Key Pair
	KeyTypeOKP = 1
	// Elliptic Curve Keys w/ x- and y-coordinate pair
	KeyTypeEC2 = 2
	// RSA Key
	KeyTypeRSA = 3
	// Symmetric Keys
	KeyTypeSymmetric = 4
	// Public key for HSS/LMS hash-based digital signature
	KeyTypeHSS_LMS = 5
	// WalnutDSA public key
	KeyTypeWalnutDSA = 6
)

// IANA-registered COSE key parameters for keys of type [KeyType::OKP].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.
const (
	// EC identifier - Taken from the "COSE Elliptic Curves" registry
	//
	// Associated value of type tstr / int
	OKPKeyParameterCrv = -1
	// x-coordinate
	//
	// Associated value of type bstr
	OKPKeyParameterX = -2
	// Private key
	//
	// Associated value of type bstr
	OKPKeyParameterD = -4
)

// IANA-registered COSE key parameters for keys of type [KeyType::EC2].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.
const (
	// EC identifier - Taken from the "COSE Elliptic Curves" registry
	//
	// Associated value of type tstr / int
	EC2KeyParameterCrv = -1
	// Public Key
	//
	// Associated value of type bstr
	EC2KeyParameterX = -2
	// y-coordinate
	//
	// Associated value of type bstr / bool
	EC2KeyParameterY = -3
	// Private key
	//
	// Associated value of type bstr
	EC2KeyParameterD = -4
)

// IANA-registered COSE key parameters for keys of type [KeyType::RSA].
//
// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
// as of 2022-12-19.
const (
	// The RSA modulus n
	//
	// Associated value of type bstr
	RSAKeyParameterN = -1
	// The RSA public exponent e
	//
	// Associated value of type bstr
	RSAKeyParameterE = -2
	// The RSA private exponent d
	//
	// Associated value of type bstr
	RSAKeyParameterD = -3
	// The prime factor p of n
	//
	// Associated value of type bstr
	RSAKeyParameterP = -4
	// The prime factor q of n
	//
	// Associated value of type bstr
	RSAKeyParameterQ = -5
	// dP is d mod (p - 1)
	//
	// Associated value of type bstr
	RSAKeyParameterDP = -6
	// dQ is d mod (q - 1)
	//
	// Associated value of type bstr
	RSAKeyParameterDQ = -7
	// qInv is the CRT coefficient q^(-1) mod p
	//
	// Associated value of type bstr
	RSAKeyParameterQInv = -8
	// Other prime infos, an array
	//
	// Associated value of type array
	RSAKeyParameterOther = -9
	// a prime factor r_i of n, where i >= 3
	//
	// Associated value of type bstr
	RSAKeyParameterRI = -10
	// d_i = d mod (r_i - 1)
	//
	// Associated value of type bstr
	RSAKeyParameterDI = -11
	// The CRT coefficient t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i
	//
	// Associated value of type bstr
	RSAKeyParameterTI = -12
)

// IANA-registered COSE key parameters for keys of type [KeyType::Symmetric].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.
const (
	// Key Value
	//
	// Associated value of type bstr
	SymmetricKeyParameterK = -1
)

// IANA-registered COSE key parameters for keys of type [KeyType::HSS_LMS].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.
const (
	// Public key for HSS/LMS hash-based digital signature
	//
	// Associated value of type bstr
	HSS_LMSKeyParameterPub = -1
)

// IANA-registered COSE key parameters for keys of type [KeyType::WalnutDSA].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.
const (
	// Group and Matrix (NxN) size
	//
	// Associated value of type uint
	WalnutDSAKeyParameterN = -1
	// Finite field F_q
	//
	// Associated value of type uint
	WalnutDSAKeyParameterQ = -2
	// List of T-values, enties in F_q
	//
	// Associated value of type array of uint
	WalnutDSAKeyParameterTValues = -3
	// NxN Matrix of enties in F_q in column-major form
	//
	// Associated value of type array of array of uint
	WalnutDSAKeyParameterMatrix1 = -4
	// Permutation associated with matrix 1
	//
	// Associated value of type array of uint
	WalnutDSAKeyParameterPermutation1 = -5
	// NxN Matrix of enties in F_q in column-major form
	//
	// Associated value of type array of array of uint
	WalnutDSAKeyParameterMatrix2 = -6
)
