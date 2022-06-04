package signatures

import (
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
)

// SignRawED25519 signs a message using an ed25519 private key with no pre-processing.
func SignRawED25519(signingKey crypto.PrivateKey, msg []byte) ([]byte, error) {
	switch pk := signingKey.(type) {
	case *ed25519.PrivateKey:
		return pk.Sign(msg)
	default:
		return nil, ErrKeyNotSupported
	}
}

// VerifyRawED25519 checks a message can be verified by the supplied ed25519 public key with no pre-processing.
func VerifyRawED25519(verificationKey crypto.PublicKey, msg, signature []byte) (bool, error) {
	switch pk := verificationKey.(type) {
	case *ed25519.PublicKey:
		return pk.Verify(msg, signature), nil
	default:
		return false, ErrKeyNotSupported
	}
}
