package mnemonic

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

func ToSeed(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 32, sha512.New)
}
