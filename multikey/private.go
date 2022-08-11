package multikey

import (
	"fmt"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
	"github.com/mailchain/mailchain/crypto/secp256k1"
	"github.com/mailchain/mailchain/crypto/sr25519"
)

// PrivateKeyFromBytes returns a private key from `[]byte`.
//
// The function used to create the private key is based on the key type.
// Supported key types are secp256k1, ed25519.
func PrivateKeyFromBytes(keyType string, data []byte) (crypto.PrivateKey, error) {
	switch keyType {
	case crypto.KindSECP256K1:
		return secp256k1.PrivateKeyFromBytes(data)
	case crypto.KindED25519:
		return ed25519.PrivateKeyFromBytes(data)
	case crypto.KindSR25519:
		return sr25519.PrivateKeyFromBytes(data)
	default:
		return nil, fmt.Errorf("unsupported key type: %q", keyType)
	}
}
