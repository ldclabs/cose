// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package iana

// CBOR Web Token (CWT) Claims
// From IANA registry <https://www.iana.org/assignments/cwt/cwt.xhtml>
// as of 2022-12-19.
const (
	// Health certificate ("hcert": map).
	CWTClaimHCert = -260
	// Challenge nonce ("EUPHNonce": bstr).
	CWTClaimEUPHNonce = -259
	// Signing prefix for multi-app restricted operating environment ("EATMAROEPrefix": bstr).
	CWTClaimEATMAROEPrefix = -258
	// FIDO Device Onboarding EAT ("EAT-FDO": array).
	CWTClaimEATFDO = -257

	// Reserved value.
	CWTClaimReserved = 0

	// Issuer ("iss": tstr).
	CWTClaimIss = 1
	// Subject ("sub": tstr)
	CWTClaimSub = 2
	// Audience ("aud": tstr)
	CWTClaimAud = 3
	// Expiration Time, as seconds since UNIX epoch ("exp": int/float)
	CWTClaimExp = 4
	// Not Before, as seconds since UNIX epoch ("nbf": int/float)
	CWTClaimNbf = 5
	// Issued at, as seconds since UNIX epoch ("iat": int/float)
	CWTClaimIat = 6
	// CWT ID ("cti": bstr)
	CWTClaimCti = 7
	// Confirmation ("cnf": map)
	CWTClaimCnf = 8
	// Scope of an access token ("scope": bstr/tstr)
	CWTClaimScope = 9
	// Nonce ("nonce": bstr) TEMPORARY, expires 2023-03-23
	CWTClaimNonce = 10

	// The ACE profile a token is supposed to be used with ("ace_profile": int)
	CWTClaimACEProfile = 38
	// The client-nonce sent to the AS by the RS via the client ("cnonce": bstr)
	CWTClaimCNonce = 39
	// The expiration time of a token measured from when it was received at the RS in seconds ("exi": int)
	CWTClaimExi = 40

	// The Universal Entity ID ("ueid": bstr) TEMPORARY, expires 2023-03-23
	CWTClaimUEID = 256
	// Hardware OEM ID ("sueids": map) TEMPORARY, expires 2023-03-23
	CWTClaimSUEIDs = 257
	// Hardware OEM ID ("oemid": bstr/int) TEMPORARY, expires 2023-03-23
	CWTClaimOEMID = 258
	// Model identifier for hardware ("hwmodel": bstr) TEMPORARY, expires 2023-03-23
	CWTClaimHWModel = 259
	// Hardware Version Identifier ("hwversion": array) TEMPORARY, expires 2023-03-23
	CWTClaimHWVersion = 260
	// Indicate whether the boot was secure ("secboot": bool) TEMPORARY, expires 2023-03-23
	CWTClaimSecureBoot = 262
	// Indicate status of debug facilities ("dbgstat": int) TEMPORARY, expires 2023-03-23
	CWTClaimDebugStatus = 263
	// The geographic location ("location": map) TEMPORARY, expires 2023-03-23
	CWTClaimLocation = 264
	// Indicates the EAT profile followed ("eat_profile": uri/oid) TEMPORARY, expires 2023-03-23
	CWTClaimProfile = 265
	// The section containing submodules ("submods": map) TEMPORARY, expires 2023-03-23
	CWTClaimSubmodules = 266

	// Reference <https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token/09/>
	// PSA Client ID (N/A: signed integer)
	CWTClaimPSAClientID = 2394
	// PSA Security Lifecycle (N/A: unsigned integer)
	CWTClaimPSASecurityLifecycle = 2395
	// PSA Implementation ID (N/A: bstr)
	CWTClaimPSAImplementationID = 2396
	// PSA Boot Seed (N/A: bstr)
	CWTClaimPSABootSeed = 2397
	// PSA Certification Reference (N/A: tstr)
	CWTClaimPSACertificationReference = 2398
	// PSA Software Components (N/A: array)
	CWTClaimPSASoftwareComponents = 2399
	// PSA Verification Service Indicator (N/A: tstr)
	CWTClaimPSAVerificationServiceIndicator = 2400
)
