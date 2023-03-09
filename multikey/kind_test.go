package multikey

import (
	"testing"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/ed25519/ed25519test"
	"github.com/mailchain/go-crypto/secp256k1/secp256k1test"
	"github.com/mailchain/go-crypto/sr25519/sr25519test"
	"github.com/stretchr/testify/assert"
)

func TestGetKeyKindFromBytes(t *testing.T) {
	type args struct {
		publicKey  []byte
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantKey crypto.PrivateKey
		wantErr error
	}{
		{
			name: "success-ed25519-alice-key",
			args: args{
				publicKey:  ed25519test.AlicePublicKey.Bytes(),
				privateKey: ed25519test.AlicePrivateKey.Bytes(),
			},
			wantKey: ed25519test.AlicePrivateKey,
		},
		{
			name: "success-ed25519-bob-key",
			args: args{
				publicKey:  ed25519test.BobPublicKey.Bytes(),
				privateKey: ed25519test.BobPrivateKey.Bytes(),
			},
			wantKey: ed25519test.BobPrivateKey,
		},
		{
			name: "success-secp256k1-alice-key",
			args: args{
				publicKey:  secp256k1test.AlicePublicKey.Bytes(),
				privateKey: secp256k1test.AlicePrivateKey.Bytes(),
			},
			wantKey: secp256k1test.AlicePrivateKey,
		},
		{
			name: "success-secp256k1-bob-key",
			args: args{
				publicKey:  secp256k1test.BobPublicKey.Bytes(),
				privateKey: secp256k1test.BobPrivateKey.Bytes(),
			},
			wantKey: secp256k1test.BobPrivateKey,
		},
		{
			name: "success-sr25519-alice-key",
			args: args{
				publicKey:  sr25519test.AlicePublicKey.Bytes(),
				privateKey: sr25519test.AlicePrivateKey.Bytes(),
			},
			wantKey: sr25519test.AlicePrivateKey,
		},
		{
			name: "success-sr25519-bob-key",
			args: args{
				publicKey:  sr25519test.BobPublicKey.Bytes(),
				privateKey: sr25519test.BobPrivateKey.Bytes(),
			},
			wantKey: sr25519test.BobPrivateKey,
		},
		{
			name: "err-invalid-public-key-bytes",
			args: args{
				publicKey:  []byte{0x1},
				privateKey: sr25519test.BobPrivateKey.Bytes(),
			},
			wantErr: ErrNoMatch,
		},
		{
			name: "err-no-key-kinds",
			args: args{
				publicKey:  []byte{0x1},
				privateKey: []byte{0x2},
			},
			wantErr: ErrNoMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GetKeyKindFromBytes(tt.args.publicKey, tt.args.privateKey)

			if !(err == tt.wantErr) {
				t.Errorf("GetKeyKindFromBytes() err = %v, want %v", err, tt.wantErr)
			}

			if !assert.Equal(t, privateKey, tt.wantKey) {
				t.Errorf("GetKeyKindFromBytes() key = %v, want %v", privateKey, tt.wantKey)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{
			[]string{"x", "x", "y"},
			[]string{"x", "y"},
		},
		{
			nil,
			nil,
		},
		{
			[]string{},
			[]string{},
		},
		{
			[]string{"c", "a", "c"},
			[]string{"c", "a"},
		},
		{
			[]string{"d", "a", "f", "a", "e", "e", "z", "f", "t"},
			[]string{"d", "a", "f", "e", "z", "t"},
		},
	}
	for _, tt := range tests {
		t.Run("remove-duplicates", func(t *testing.T) {
			got := removeDuplicates(tt.in)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("removeDuplicates() = %v, want %v", got, tt.want)
			}
		})
	}
}
