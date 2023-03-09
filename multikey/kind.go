package multikey

import (
	"bytes"
	"errors"

	"github.com/mailchain/go-crypto"
)

var (
	// ErrInconclusive is returned when multiple public keys matches for the same input.
	ErrInconclusive = errors.New("multiple matches found")

	// ErrNoMatch is returned when no public key matches for the input.
	ErrNoMatch = errors.New("no match found")

	// errPrivateKeyPublicKeyNotMatched private and public keys do not match
	errPrivateAndPublicKeyNotMatched = errors.New("public and private keys do not match")
)

const (
	noKeyMatch     = 0
	singleKeyMatch = 1
)

// GetKeyKindFromBytes extracts the private key type from the publicKey and privateKey.
// Supported private key types are defined in PossibleKeyKinds variable.
func GetKeyKindFromBytes(publicKey, privateKey []byte) (crypto.PrivateKey, error) {
	matches := make([]crypto.PrivateKey, 0, 1)

	for keyKind := range crypto.KeyTypes() {
		cPrivateKey, err := extractKeyTypeAndVerifyPrivateAndPublicKey(publicKey, privateKey, keyKind)
		if err != nil {
			continue
		}

		matches = append(matches, cPrivateKey)
	}

	switch len(matches) {
	case noKeyMatch:
		return nil, ErrNoMatch
	case singleKeyMatch:
		return matches[0], nil
	default:
		return nil, ErrInconclusive
	}
}

func extractKeyTypeAndVerifyPrivateAndPublicKey(publicKey, privateKey []byte, kind string) (crypto.PrivateKey, error) {
	cPrivateKey, err := PrivateKeyFromBytes(kind, privateKey)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(cPrivateKey.PublicKey().Bytes(), publicKey) {
		return cPrivateKey, nil
	}

	return nil, errPrivateAndPublicKeyNotMatched
}

func removeDuplicates(x []string) []string {
	if x == nil {
		return nil
	}

	set := make(map[string]struct{})
	unique := []string{}

	for _, str := range x {
		if _, ok := set[str]; !ok {
			set[str] = struct{}{}

			unique = append(unique, str)
		}
	}

	return unique
}
