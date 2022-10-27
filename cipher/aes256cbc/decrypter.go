package aes256cbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/andreburgaud/crypt2go/padding"
	"github.com/mailchain/go-crypto"
	mc "github.com/mailchain/go-crypto/cipher"
	"github.com/mailchain/go-crypto/secp256k1"
)

// NewDecrypter create a new decrypter attaching the private key to it
func NewDecrypter(privateKey crypto.PrivateKey) (*Decrypter, error) {
	if err := validatePrivateKeyType(privateKey); err != nil {
		return nil, err
	}

	return &Decrypter{privateKey: privateKey}, nil
}

// Decrypter will decrypt data using AES256CBC method
type Decrypter struct {
	privateKey crypto.PrivateKey
}

// Decrypt data using recipient private key with AES in CBC mode.
func (d Decrypter) Decrypt(data mc.EncryptedContent) (mc.PlainContent, error) {
	encryptedData, err := bytesDecode(data)
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	return decryptEncryptedData(d.privateKey, encryptedData)
}

func decryptEncryptedData(privKey crypto.PrivateKey, data *encryptedData) ([]byte, error) {
	tmpEphemeralPublicKey, err := secp256k1.PublicKeyFromBytes(data.EphemeralPublicKey)
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	ephemeralPublicKey, err := tmpEphemeralPublicKey.(*secp256k1.PublicKey).ECIES()
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	recipientPrivKey, err := asPrivateECIES(privKey)
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	sharedSecret, err := deriveSharedSecret(ephemeralPublicKey, recipientPrivKey)
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	macKey, encryptionKey := generateMacKeyAndEncryptionKey(sharedSecret)
	mac, err := generateMac(macKey, data.InitializationVector, *ephemeralPublicKey, data.Ciphertext)

	if err != nil {
		return nil, mc.ErrDecrypt
	}

	if subtle.ConstantTimeCompare(data.MessageAuthenticationCode, mac) != 1 {
		return nil, mc.ErrDecrypt
	}
	return decryptCBC(encryptionKey, data.InitializationVector, data.Ciphertext)
}

func decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	plaintext, err = padding.NewPkcs7Padding(block.BlockSize()).Unpad(plaintext)
	if err != nil {
		return nil, mc.ErrDecrypt
	}

	ret := make([]byte, len(plaintext))
	copy(ret, plaintext)

	return ret, nil
}

func validatePrivateKeyType(privateKey crypto.PrivateKey) error {
	switch privateKey.(type) {
	case *secp256k1.PrivateKey:
		return nil
	default:
		return errors.New("invalid private key type for aes256cbc decryption")
	}
}
