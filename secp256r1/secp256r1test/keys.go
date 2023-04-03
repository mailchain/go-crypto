// Package secp256k1test contains keys that are used to ease testing of Mailchain
// functionality.
// All keys in this package are publicly known and therefore compromised. Keys
// MUST not be used on any live networks, as secrets, or for any purpose other
// than creating a reproducible unsecured test.
package secp256r1test

import (
	"log"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/secp256r1"
	"github.com/mailchain/go-encoding/encodingtest"
)

// AlicePrivateKey secp256k1 key for testing purposes. Key is compromised do not use on mainnet's.
var AlicePrivateKey crypto.PrivateKey //nolint: gochecknoglobals
// AlicePublicKey secp256k1 key for testing purposes. Key is compromised do not use on mainnet's.
var AlicePublicKey crypto.PublicKey //nolint: gochecknoglobals
// BobPrivateKey secp256k1 key for testing purposes. Key is compromised do not use on mainnet's.
var BobPrivateKey crypto.PrivateKey //nolint: gochecknoglobals
// BobPublicKey secp256k1 key for testing purposes. Key is compromised do not use on mainnet's.
var BobPublicKey crypto.PublicKey //nolint: gochecknoglobals

// CarlosPrivateKey secp256k1 key for testing purposes. Key is compromised do not use on mainnet's.
var CarlosPrivateKey crypto.PrivateKey //nolint: gochecknoglobals
// CarlosPublicKey secp256k1 key for testing purposes. Key is compromised do not use on mainnet's.
var CarlosPublicKey crypto.PublicKey //nolint: gochecknoglobals

//nolint: gochecknoinits
func init() {
	var err error

	AlicePrivateKey, err = secp256r1.PrivateKeyFromBytes(encodingtest.MustDecodeHex("3cdee0ff28337463455cd1cc43d29b1bf749d9615576525853ccc02b83c8b433"))
	if err != nil {
		log.Fatal(err)
	}

	AlicePublicKey = AlicePrivateKey.PublicKey()

	BobPrivateKey, err = secp256r1.PrivateKeyFromBytes(encodingtest.MustDecodeHex("a1e65c4677435cea57950b39379a9ec7ec0c64edc97efe36cdaae3c386fe2b71"))
	if err != nil {
		log.Fatal(err)
	}

	BobPublicKey = BobPrivateKey.PublicKey()

	CarlosPrivateKey, err = secp256r1.PrivateKeyFromBytes(encodingtest.MustDecodeHex("7198ec54092518b49b2c66468a058f1fdbf0fdf0b1e281a027c692bb0ee1d1ed"))
	if err != nil {
		log.Fatal(err)
	}

	CarlosPublicKey = CarlosPrivateKey.PublicKey()

}
