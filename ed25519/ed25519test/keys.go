// Package ed25519test contains keys that are used to ease testing of Mailchain
// functionality.
// All keys in this package are publicly known and therefore compromised. Keys
// MUST not be used on any live networks, as secrets, or for any purpose other
// than creating a reproducible unsecured test.

package ed25519test

import (
	"log"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
	"github.com/mailchain/mailchain/encoding/encodingtest"
)

// AlicePrivateKey ed25519 key for testing purposes. Key is compromised do not use on mainnet's.
var AlicePrivateKey crypto.PrivateKey //nolint: gochecknoglobals
// AlicePublicKey ed25519 key for testing purposes. Key is compromised do not use on mainnet's.
var AlicePublicKey crypto.PublicKey //nolint: gochecknoglobals
// BobPrivateKey ed25519 key for testing purposes. Key is compromised do not use on mainnet's.
var BobPrivateKey crypto.PrivateKey //nolint: gochecknoglobals
// BobPublicKey ed25519 key for testing purposes. Key is compromised do not use on mainnet's.
var BobPublicKey crypto.PublicKey //nolint: gochecknoglobals

// CharliePrivateKey ed25519 key for testing purposes. Key is compromised do not use on mainnet's.
var CharliePrivateKey crypto.PrivateKey //nolint: gochecknoglobals
// CharliePublicKey ed25519 key for testing purposes. Key is compromised do not use on mainnet's.
var CharliePublicKey crypto.PublicKey //nolint: gochecknoglobals

//nolint: gochecknoinits
func init() {
	var err error
	AlicePrivateKey, err = ed25519.PrivateKeyFromBytes(encodingtest.MustDecodeHex("0d9b4a3c10721991c6b806f0f343535dc2b46c74bece50a0a0d6b9f0070d3157"))
	if err != nil {
		log.Fatal(err)
	}

	AlicePublicKey = AlicePrivateKey.PublicKey()

	BobPrivateKey, err = ed25519.PrivateKeyFromBytes(encodingtest.MustDecodeHex("39d4c97d6a7f9e3306a2b5aae604ee67ec8b1387fffb39128fc055656cff05bb"))
	if err != nil {
		log.Fatal(err)
	}

	BobPublicKey = BobPrivateKey.PublicKey()

	CharliePrivateKey, err = ed25519.PrivateKeyFromBytes(encodingtest.MustDecodeHex("cd81ad6a71da3cbe070c6e73a6ab591a9987a3e6ce2ba2ef6c2a3846ed3cdb08"))
	if err != nil {
		log.Fatal(err)
	}

	CharliePublicKey = CharliePrivateKey.PublicKey()
}
