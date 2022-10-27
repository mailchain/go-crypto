package nacl

import (
	"errors"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/cipher"
	"github.com/mailchain/go-crypto/multikey"
)

// NewPrivateKeyDecrypter create a new decrypter attaching the private key to it
func NewPrivateKeyDecrypter(privateKey crypto.PrivateKey) (*PrivateKeyDecrypter, error) {
	keyExchange, err := getPrivateKeyExchange(privateKey)
	if err != nil {
		return nil, err
	}

	return &PrivateKeyDecrypter{privateKey: privateKey, keyExchange: keyExchange}, nil
}

// PrivateKeyDecrypter will decrypt data using NACL with ECDH key exchange
type PrivateKeyDecrypter struct {
	privateKey  crypto.PrivateKey
	keyExchange cipher.KeyExchange
}

// Decrypt data using recipient private key with AES in CBC mode.
func (d PrivateKeyDecrypter) Decrypt(data cipher.EncryptedContent) (cipher.PlainContent, error) {
	data, deserialiseKeyID, err := deserializePrivateKeyEncryptedContent(data)
	if err != nil {
		return nil, err
	}

	privateKeyID, err := multikey.IDFromPrivateKey(d.privateKey)
	if err != nil {
		return nil, err
	}

	if deserialiseKeyID != privateKeyID {
		return nil, errors.New("key id does not match")
	}

	encryptionKeyBytes, err := encryptionKeyBytes(d.privateKey)
	if err != nil {
		return nil, err
	}

	return easyOpen(data, encryptionKeyBytes)
}
