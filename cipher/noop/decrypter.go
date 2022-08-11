package noop

import (
	"github.com/mailchain/mailchain/crypto/cipher"
)

// NewDecrypter create a new decrypter attaching the private key to it
func NewDecrypter() Decrypter {
	return Decrypter{}
}

// Decrypter will decrypt data using AES256CBC method
type Decrypter struct {
}

// Decrypt data using recipient private key with AES in CBC mode.
func (d Decrypter) Decrypt(data cipher.EncryptedContent) (cipher.PlainContent, error) {
	content, err := bytesDecode(data)
	return cipher.PlainContent(content), err
}
