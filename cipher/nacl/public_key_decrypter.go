package nacl

import (
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/cipher"
)

// NewPublicKeyDecrypter create a new decrypter attaching the private key to it
func NewPublicKeyDecrypter(privateKey crypto.PrivateKey) (*PublicKeyDecrypter, error) {
	keyExchange, err := getPrivateKeyExchange(privateKey)
	if err != nil {
		return nil, err
	}

	return &PublicKeyDecrypter{privateKey: privateKey, keyExchange: keyExchange}, nil
}

// PublicKeyDecrypter will decrypt data using NACL with ECDH key exchange
type PublicKeyDecrypter struct {
	privateKey  crypto.PrivateKey
	keyExchange cipher.KeyExchange
}

// Decrypt data using recipient private key with AES in CBC mode.
func (d PublicKeyDecrypter) Decrypt(data cipher.EncryptedContent) (cipher.PlainContent, error) {
	data, pubKey, err := deserializePublicKeyEncryptedContent(data)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := d.keyExchange.SharedSecret(d.privateKey, pubKey)
	if err != nil {
		return nil, err
	}

	return easyOpen(data, sharedSecret)
}
