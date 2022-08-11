package aes256cbc

import "errors"

type encryptedData struct {
	InitializationVector      []byte `json:"iv"`
	EphemeralPublicKey        []byte `json:"ephemPublicKey"`
	Ciphertext                []byte `json:"ciphertext"`
	MessageAuthenticationCode []byte `json:"mac"`
}

func (e *encryptedData) verify() error {
	if len(e.InitializationVector) != 16 {
		return errors.New("`InitializationVector` must be 16")
	}

	if len(e.EphemeralPublicKey) != 65 {
		return errors.New("`EphemeralPublicKey` must be 65")
	}

	if len(e.MessageAuthenticationCode) != 32 {
		return errors.New("`MessageAuthenticationCode` must be 16")
	}

	if len(e.Ciphertext) == 0 {
		return errors.New("`Ciphertext` must not be empty")
	}

	return nil
}
