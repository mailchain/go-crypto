package nacl

import (
	"errors"

	"github.com/agl/ed25519/extra25519"
	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/ed25519"
	"github.com/mailchain/go-crypto/secp256k1"
	"github.com/mailchain/go-crypto/sr25519"
)

func encryptionKeyBytes(privateKey crypto.PrivateKey) ([]byte, error) {
	switch key := privateKey.(type) {
	case *ed25519.PrivateKey, ed25519.PrivateKey:
		var ed25519Key [64]byte
		var out [32]byte
		copy(ed25519Key[:], key.Bytes())
		extra25519.PrivateKeyToCurve25519(&out, &ed25519Key)

		return out[:], nil
	case *secp256k1.PrivateKey, secp256k1.PrivateKey:
		return key.Bytes(), nil
	case *sr25519.PrivateKey, sr25519.PrivateKey:
		return nil, errors.New("sr25519 private keys are not supported")
	default:
		return nil, errors.New("unknown private key type")
	}
}
