package noop

import (
	"fmt"

	"github.com/mailchain/mailchain/crypto/cipher"
)

// bytesEncode encode the encrypted data to the hex format
func bytesEncode(data cipher.EncryptedContent) cipher.EncryptedContent {
	encodedData := make(cipher.EncryptedContent, 1+len(data))
	encodedData[0] = cipher.NoOperation
	copy(encodedData[1:], data)

	return encodedData
}

// bytesDecode convert the hex format in to the encrypted data format
func bytesDecode(raw cipher.EncryptedContent) (cipher.EncryptedContent, error) {
	if raw[0] != cipher.NoOperation {
		return nil, fmt.Errorf("invalid prefix")
	}

	return raw[1:], nil
}
