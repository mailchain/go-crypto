package multikey

import (
	"testing"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519/ed25519test"
	"github.com/mailchain/mailchain/crypto/secp256k1/secp256k1test"
	"github.com/mailchain/mailchain/crypto/sr25519/sr25519test"
	"github.com/mailchain/mailchain/encoding/encodingtest"
	"github.com/stretchr/testify/assert"
)

func TestPrivateKeyFromBytes(t *testing.T) {
	type args struct {
		hex     string
		keyType []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr bool
	}{
		{
			"secp256k1",
			args{
				"secp256k1",
				secp256k1test.AlicePrivateKey.Bytes(),
			},
			secp256k1test.AlicePrivateKey,
			false,
		},
		{
			"ed25519",
			args{
				"ed25519",
				ed25519test.AlicePrivateKey.Bytes(),
			},
			ed25519test.AlicePrivateKey,
			false,
		},
		{
			"sr25519-Bob",
			args{
				"sr25519",
				encodingtest.MustDecodeHex("23b063a581fd8e5e847c4e2b9c494247298791530f5293be369e8bf23a45d2bd"),
			},
			sr25519test.BobPrivateKey,
			false,
		},
		{
			"err",
			args{
				"unknown",
				secp256k1test.AlicePrivateKey.Bytes(),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrivateKeyFromBytes(tt.args.hex, tt.args.keyType)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKeyFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("PrivateKeyFromBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
