package multikey

import (
	"errors"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/ed25519"
	"github.com/mailchain/go-crypto/secp256k1"
	"github.com/mailchain/go-crypto/secp256r1"
	"github.com/mailchain/go-crypto/sr25519"
)

func IDFromPublicKey(key crypto.PublicKey) (byte, error) {
	switch key.(type) {
	case *ed25519.PublicKey, ed25519.PublicKey:
		return crypto.IDED25519, nil
	case *secp256k1.PublicKey, secp256k1.PublicKey:
		return crypto.IDSECP256K1, nil
	case *secp256r1.PublicKey, secp256r1.PublicKey:
		return crypto.IDSECP256R1, nil
	case *sr25519.PublicKey, sr25519.PublicKey:
		return crypto.IDSR25519, nil
	default:
		return crypto.IDUnknown, errors.New("unknown public key type")
	}
}

func IDFromPrivateKey(key crypto.PrivateKey) (byte, error) {
	switch key.(type) {
	case *ed25519.PrivateKey, ed25519.PrivateKey:
		return crypto.IDED25519, nil
	case *secp256k1.PrivateKey, secp256k1.PrivateKey:
		return crypto.IDSECP256K1, nil
	case *secp256r1.PrivateKey, secp256r1.PrivateKey:
		return crypto.IDSECP256R1, nil
	case *sr25519.PrivateKey, sr25519.PrivateKey:
		return crypto.IDSR25519, nil
	default:
		return crypto.IDUnknown, errors.New("unknown private key type")
	}
}
