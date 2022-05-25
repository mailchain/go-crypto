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

package multikey

import (
	"errors"
	"fmt"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
	"github.com/mailchain/mailchain/crypto/secp256k1"
	"github.com/mailchain/mailchain/crypto/sr25519"
	"github.com/mailchain/mailchain/encoding"
)

// PublicKeyFromBytes use the correct function to get the private key from bytes
func PublicKeyFromBytes(keyType string, data []byte) (crypto.PublicKey, error) {
	switch keyType {
	case crypto.KindSECP256K1:
		return secp256k1.PublicKeyFromBytes(data)
	case crypto.KindED25519:
		return ed25519.PublicKeyFromBytes(data)
	case crypto.KindSR25519:
		return sr25519.PublicKeyFromBytes(data)
	default:
		return nil, fmt.Errorf("unsupported curve type")
	}
}

func DescriptivePublicKeyFromEncodedString(in string, encodedWith string) (crypto.PublicKey, error) {
	decodedBytes, err := encoding.Decode(encodedWith, in)
	if err != nil {
		return nil, err
	}

	return DescriptivePublicKeyFromBytes(decodedBytes)
}

func DescriptivePublicKeyFromBytes(in []byte) (crypto.PublicKey, error) {
	if len(in) <= 1 {
		return nil, errors.New("input must contain id and public key")
	}

	keyType := in[0]
	data := in[1:] // skip the id byte and return rest

	switch keyType {
	case crypto.IDSECP256K1:
		return secp256k1.PublicKeyFromBytes(data)
	case crypto.IDED25519:
		return ed25519.PublicKeyFromBytes(data)
	case crypto.IDSR25519:
		return sr25519.PublicKeyFromBytes(data)
	default:
		return nil, fmt.Errorf("first byte must identity key curve")
	}
}

func DescriptiveBytesFromPublicKey(in crypto.PublicKey) ([]byte, error) {
	idByte, err := IDFromPublicKey(in)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(in.Bytes())+1)
	out[0] = idByte
	copy(out[1:], in.Bytes())

	return out, nil
}
