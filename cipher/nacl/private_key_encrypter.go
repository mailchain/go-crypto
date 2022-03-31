package nacl

import (
	"crypto/rand"
	"io"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/cipher"
	"github.com/mailchain/mailchain/crypto/multikey"
	"github.com/pkg/errors"
)

// NewPrivateKeyEncrypter creates a new encrypter with crypto rand for reader,
// and attaching the public key to the encrypter.
func NewPrivateKeyEncrypter(privateKey crypto.PrivateKey) (*PrivateKeyEncrypter, error) {
	keyExchange, err := getPrivateKeyExchange(privateKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &PrivateKeyEncrypter{rand: rand.Reader, privateKey: privateKey, keyExchange: keyExchange}, nil
}

// PrivateKeyEncrypter will encrypt data using AES256CBC method.
type PrivateKeyEncrypter struct {
	rand        io.Reader
	privateKey  crypto.PrivateKey
	keyExchange cipher.KeyExchange
}

// Encrypt encrypts the message with the key that was attached to it.
func (e PrivateKeyEncrypter) Encrypt(message cipher.PlainContent) (cipher.EncryptedContent, error) {
	encryptionKeyBytes, err := encryptionKeyBytes(e.privateKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := easySeal(message, encryptionKeyBytes, e.rand)
	if err != nil {
		return nil, err
	}

	keyID, err := multikey.IDFromPrivateKey(e.privateKey)
	if err != nil {
		return nil, err
	}

	return serializePrivateKeyEncryptedContent(encrypted, keyID), nil
}
