package nacl

import (
	"crypto/rand"
	"io"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/cipher"
)

// NewPublicKeyEncrypter creates a new encrypter with crypto rand for reader,
// and attaching the public key to the encrypter.
func NewPublicKeyEncrypter(publicKey crypto.PublicKey) (*PublicKeyEncrypter, error) {
	keyExchange, err := getPublicKeyExchange(publicKey)
	if err != nil {
		return nil, err
	}

	return &PublicKeyEncrypter{rand: rand.Reader, publicKey: publicKey, keyExchange: keyExchange}, nil
}

// PublicKeyEncrypter will encrypt data using AES256CBC method.
type PublicKeyEncrypter struct {
	rand        io.Reader
	publicKey   crypto.PublicKey
	keyExchange cipher.KeyExchange
}

// Encrypt encrypts the message with the key that was attached to it.
func (e PublicKeyEncrypter) Encrypt(message cipher.PlainContent) (cipher.EncryptedContent, error) {
	ephemeralKey, err := e.keyExchange.EphemeralKey()
	if err != nil {
		return nil, err
	}

	sharedSecret, err := e.keyExchange.SharedSecret(ephemeralKey, e.publicKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := easySeal(message, sharedSecret, e.rand)
	if err != nil {
		return nil, err
	}

	return serializePublicKeyEncryptedContent(encrypted, ephemeralKey.PublicKey())
}
