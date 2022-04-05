package signatures

import (
	"fmt"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
)

func mailchainUsernameMessage(username []byte) []byte {
	return []byte(fmt.Sprintf("\x11Mailchain username ownership:\n%d\n%s", len(username), string(username)))
}

// SignMailchainUsername signs a message using the Mailchain username with the identity private key.
func SignMailchainUsername(key crypto.PrivateKey, username []byte) ([]byte, error) {
	switch pk := key.(type) {
	case *ed25519.PrivateKey:
		msg := mailchainUsernameMessage(username)

		return pk.Sign(msg)
	default:
		return nil, ErrKeyNotSupported
	}
}

// VerifyMailchainUsername verifies a message linking a username with an identity key is valid.
func VerifyMailchainUsername(key crypto.PublicKey, username, signature []byte) (bool, error) {
	switch pk := key.(type) {
	case *ed25519.PublicKey:
		msg := mailchainUsernameMessage(username)

		return pk.Verify(msg, signature), nil
	default:
		return false, ErrKeyNotSupported
	}
}
