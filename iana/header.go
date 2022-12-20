// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package iana

// IANA-registered COSE header parameters.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
// as of 2022-12-19.
const (
	// Reserved
	HeaderParameterReserved = 0
	// Cryptographic algorithm to use
	//
	// Associated value of type int / tstr
	HeaderParameterAlg = 1
	// Critical headers to be understood
	//
	// Associated value of type [+ label]
	HeaderParameterCrit = 2
	// Content type of the payload
	//
	// Associated value of type tstr / uint
	HeaderParameterContentType = 3
	// Key identifier
	//
	// Associated value of type bstr
	HeaderParameterKid = 4
	// Full Initialization Vector
	//
	// Associated value of type bstr
	HeaderParameterIV = 5
	// Partial Initialization Vector
	//
	// Associated value of type bstr
	HeaderParameterPartialIV = 6
	// CBOR-encoded signature structure
	//
	// Associated value of type COSE_Signature / [+ COSE_Signature ]
	HeaderParameterCounterSignature = 7
	// Counter signature with implied signer and headers
	//
	// Associated value of type bstr
	HeaderParameterCounterSignature0 = 9
	// Identifies the context for the key identifier
	//
	// Associated value of type bstr
	HeaderParameterKidContext = 10
	// V2 countersignature attribute
	//
	// Associated value of type COSE_Countersignature / [+ COSE_Countersignature]
	HeaderParameterCountersignatureV2 = 11
	// V2 Abbreviated Countersignature
	//
	// Associated value of type COSE_Countersignature0
	HeaderParameterCountersignature0V2 = 11
	// An unordered bag of X.509 certificates
	//
	// Associated value of type COSE_X509
	HeaderParameterX5Bag = 32
	// An ordered chain of X.509 certificates
	//
	// Associated value of type COSE_X509
	HeaderParameterX5Chain = 33
	// Hash of an X.509 certificate
	//
	// Associated value of type COSE_CertHash
	HeaderParameterX5T = 34
	// URI pointing to an X.509 certificate
	//
	// Associated value of type uri
	HeaderParameterX5U = 35
	// Challenge Nonce
	//
	// Associated value of type bstr
	HeaderParameterCuphNonce = 256
	// Public Key
	//
	// Associated value of type array
	HeaderParameterCuphOwnerPubKey = 257
)

// IANA-registered COSE header algorithm parameters.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters
// as of 2022-12-19.
const (
	// static key X.509 certificate chain
	//
	// Associated value of type COSE_X509
	HeaderAlgorithmParameterX5ChainSender = -29
	// URI for the sender's X.509 certificate
	//
	// Associated value of type uri
	HeaderAlgorithmParameterX5USender = -28
	// Thumbprint for the sender's X.509 certificate
	//
	// Associated value of type COSE_CertHash
	HeaderAlgorithmParameterX5TSender = -27
	// Party V other provided information
	//
	// Associated value of type bstr
	HeaderAlgorithmParameterPartyVOther = -26
	// Party V provided nonce
	//
	// Associated value of type bstr / int
	HeaderAlgorithmParameterPartyVNonce = -25
	// Party V identity information
	//
	// Associated value of type bstr
	HeaderAlgorithmParameterPartyVIdentity = -24
	// Party U other provided information
	//
	// Associated value of type bstr
	HeaderAlgorithmParameterPartyUOther = -23
	// Party U provided nonce
	//
	// Associated value of type bstr / int
	HeaderAlgorithmParameterPartyUNonce = -22
	// Party U identity information
	//
	// Associated value of type bstr
	HeaderAlgorithmParameterPartyUIdentity = -21
	// Random salt
	//
	// Associated value of type bstr
	HeaderAlgorithmParameterSalt = -20
	// Static public key identifier for the sender
	//
	// Associated value of type bstr
	HeaderAlgorithmParameterStaticKeyId = -3
	// Static public key for the sender
	//
	// Associated value of type COSE_Key
	HeaderAlgorithmParameterStaticKey = -2
	// Ephemeral public key for the sender
	//
	// Associated value of type COSE_Key
	HeaderAlgorithmParameterEphemeralKey = -1
)
