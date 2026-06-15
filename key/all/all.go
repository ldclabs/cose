// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package all imports the built-in COSE algorithm packages.
//
// Import this package for its side effects when an application, generated code,
// or example wants the standard algorithm implementations registered through
// the key package registry without listing every algorithm package separately:
//
//	import _ "github.com/ldclabs/cose/key/all"
//
// The signing, encryption, and MAC packages register factories from their init
// functions. The ECDH and HKDF packages expose helper APIs rather than registry
// factories, but they are included here so one import makes the built-in
// algorithm surface discoverable to tooling.
package all

import (
	_ "github.com/ldclabs/cose/key/aesccm"
	_ "github.com/ldclabs/cose/key/aesgcm"
	_ "github.com/ldclabs/cose/key/aesmac"
	_ "github.com/ldclabs/cose/key/chacha20poly1305"
	_ "github.com/ldclabs/cose/key/ecdh"
	_ "github.com/ldclabs/cose/key/ecdsa"
	_ "github.com/ldclabs/cose/key/ed25519"
	_ "github.com/ldclabs/cose/key/hkdf"
	_ "github.com/ldclabs/cose/key/hmac"
)
