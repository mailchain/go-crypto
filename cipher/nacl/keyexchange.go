package nacl

import (
	"crypto/rand"
	"fmt"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/cipher"
	"github.com/mailchain/go-crypto/cipher/ecdh"
	"github.com/mailchain/go-crypto/ed25519"
	"github.com/mailchain/go-crypto/secp256k1"
	"github.com/mailchain/go-crypto/sr25519"
)

func getPublicKeyExchange(recipientPublicKey crypto.PublicKey) (cipher.KeyExchange, error) {
	switch recipientPublicKey.(type) {
	case ed25519.PublicKey, *ed25519.PublicKey:
		return ecdh.NewED25519(rand.Reader)
	case sr25519.PublicKey, *sr25519.PublicKey:
		return ecdh.NewSR25519(rand.Reader)
	case secp256k1.PublicKey, *secp256k1.PublicKey:
		return ecdh.NewSECP256K1(rand.Reader)
	default:
		return nil, fmt.Errorf("invalid public key type for nacl encryption")
	}
}

func getPrivateKeyExchange(pk crypto.PrivateKey) (cipher.KeyExchange, error) {
	switch pk.(type) {
	case *ed25519.PrivateKey:
		return ecdh.NewED25519(rand.Reader)
	case *sr25519.PrivateKey:
		return ecdh.NewSR25519(rand.Reader)
	case *secp256k1.PrivateKey:
		return ecdh.NewSECP256K1(rand.Reader)
	default:
		return nil, fmt.Errorf("invalid private key type for nacl decryption")
	}
}
