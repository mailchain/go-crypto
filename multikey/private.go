package multikey

import (
	"fmt"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/ed25519"
	"github.com/mailchain/go-crypto/secp256k1"
	"github.com/mailchain/go-crypto/sr25519"
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

func DescriptiveBytesFromPrivateKey(in crypto.PrivateKey) ([]byte, error) {
	idByte, err := IDFromPrivateKey(in)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(in.Bytes())+1)
	out[0] = idByte
	copy(out[1:], in.Bytes())

	return out, nil
}
