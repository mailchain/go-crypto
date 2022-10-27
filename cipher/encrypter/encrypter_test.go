package encrypter

import (
	"testing"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/cipher"
	"github.com/mailchain/go-crypto/cipher/aes256cbc"
	"github.com/mailchain/go-crypto/cipher/nacl"
	"github.com/mailchain/go-crypto/cipher/noop"
	"github.com/mailchain/go-crypto/secp256k1/secp256k1test"
	"github.com/stretchr/testify/assert"
)

func TestGetEncrypter(t *testing.T) {
	type args struct {
		encryption string
		pubKey     crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    cipher.Encrypter
		wantErr bool
	}{
		{
			"aes256cbc",
			args{
				"aes256cbc",
				secp256k1test.AlicePublicKey,
			},
			func() cipher.Encrypter {
				encrypter, _ := aes256cbc.NewEncrypter(secp256k1test.AlicePublicKey)
				return encrypter
			}(),
			false,
		},
		{
			"nacl-ecdh",
			args{
				"nacl-ecdh",
				secp256k1test.AlicePublicKey,
			},
			func() cipher.Encrypter {
				encrypter, _ := nacl.NewPublicKeyEncrypter(secp256k1test.AlicePublicKey)
				return encrypter
			}(),
			false,
		},
		{
			"noop",
			args{
				"noop",
				secp256k1test.AlicePublicKey,
			},
			func() cipher.Encrypter {
				encrypter, _ := noop.NewEncrypter(secp256k1test.AlicePublicKey)
				return encrypter
			}(),
			false,
		},
		{
			"err-empty",
			args{
				"",
				secp256k1test.AlicePublicKey,
			},
			nil,
			true,
		},
		{
			"err-invalid",
			args{
				"invalid",
				secp256k1test.AlicePublicKey,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetEncrypter(tt.args.encryption, tt.args.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEncrypter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("GetEncrypter() = %v, want %v", got, tt.want)
			}
		})
	}
}
