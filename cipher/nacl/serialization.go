// Copyright 2022 Mailchain Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nacl

import (
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/cipher"
	"github.com/mailchain/mailchain/crypto/ed25519"
	"github.com/mailchain/mailchain/crypto/secp256k1"
	"github.com/mailchain/mailchain/crypto/sr25519"
	"github.com/pkg/errors"
)

func pubKeyElements(pubKey crypto.PublicKey) (id byte, data []byte, err error) {
	switch pk := pubKey.(type) {
	case *secp256k1.PublicKey:
		id = crypto.IDSECP256K1
		data = pk.Bytes()
	case *ed25519.PublicKey:
		id = crypto.IDED25519
		data = pk.Bytes()
	case *sr25519.PublicKey:
		id = crypto.IDSR25519
		data = pk.Bytes()
	default:
		err = errors.New("unsupported public key")
	}

	return
}

// serializePublicKeyEncryptedContent encode the encrypted data to the hex format
func serializePublicKeyEncryptedContent(data cipher.EncryptedContent, pubKey crypto.PublicKey) (cipher.EncryptedContent, error) {
	pkID, pkBytes, err := pubKeyElements(pubKey)
	if err != nil {
		return nil, err
	}

	pkLen := len(pkBytes)
	encodedData := make(cipher.EncryptedContent, 2+len(data)+pkLen)
	encodedData[0] = cipher.NACLECDH
	encodedData[1] = pkID
	copy(encodedData[2:2+pkLen], pkBytes)
	copy(encodedData[2+pkLen:], data)

	return encodedData, nil
}

func serializePrivateKeyEncryptedContent(sealedBox cipher.EncryptedContent, keyID byte) cipher.EncryptedContent {
	out := make(cipher.EncryptedContent, 2+len(sealedBox))
	out[0] = cipher.NACLSecretKey
	out[1] = byte(keyID)
	copy(out[2:], sealedBox)

	return out
}

// deserializePublicKeyEncryptedContent convert the hex format in to the encrypted data format
func deserializePublicKeyEncryptedContent(raw cipher.EncryptedContent) (cph cipher.EncryptedContent, pubKey crypto.PublicKey, err error) {
	if raw[0] != cipher.NACLECDH {
		return nil, nil, errors.Errorf("invalid prefix")
	}

	if len(raw) < 35 {
		return nil, nil, errors.Errorf("cipher is too short") // will result in error is less than this
	}

	switch raw[1] {
	case crypto.IDED25519:
		pubKey, err = ed25519.PublicKeyFromBytes(raw[2:34])
		cph = raw[34:]
	case crypto.IDSR25519:
		pubKey, err = sr25519.PublicKeyFromBytes(raw[2:34])
		cph = raw[34:]
	case crypto.IDSECP256K1:
		pubKey, err = secp256k1.PublicKeyFromBytes(raw[2:35])
		cph = raw[35:]
	default:
		return nil, nil, errors.New("unrecognized pubKeyID")
	}

	return cph, pubKey, err
}

// deserializePrivateKeyEncryptedContent convert the hex format in to the encrypted data format
func deserializePrivateKeyEncryptedContent(raw cipher.EncryptedContent) (cph cipher.EncryptedContent, keyID byte, err error) {
	if raw[0] != cipher.NACLSecretKey {
		return nil, 0x0, errors.Errorf("invalid prefix")
	}

	if len(raw) < 3 {
		return nil, 0x0, errors.Errorf("cipher is too short") // will result in error is less than this
	}

	return raw[2:], raw[1], err
}
