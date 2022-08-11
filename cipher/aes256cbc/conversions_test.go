package aes256cbc

import (
	"testing"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519/ed25519test"
	"github.com/mailchain/mailchain/crypto/secp256k1"
	"github.com/mailchain/mailchain/crypto/secp256k1/secp256k1test"
	"github.com/mailchain/mailchain/crypto/sr25519/sr25519test"
)

func Test_asPrivateECIES(t *testing.T) {
	type args struct {
		pk crypto.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			"success-secp256k1-alice-val",
			args{
				func() secp256k1.PrivateKey {
					t := secp256k1test.AlicePrivateKey.(*secp256k1.PrivateKey)
					return *t
				}(),
			},
			false,
			false,
		},
		{
			"success-secp256k1-alice-pointer",
			args{
				func() *secp256k1.PrivateKey {
					return secp256k1test.AlicePrivateKey.(*secp256k1.PrivateKey)
				}(),
			},
			false,
			false,
		},
		{
			"err-unsupported",
			args{
				ed25519test.AlicePrivateKey,
			},
			true,
			true,
		},
		{
			"err-unsupported-sr25519",
			args{
				sr25519test.AlicePrivateKey,
			},
			true,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asPrivateECIES(tt.args.pk)
			if (err != nil) != tt.wantErr {
				t.Errorf("asPrivateECIES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (got == nil) != tt.wantNil {
				t.Errorf("asPrivateECIES() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}

func Test_asPublicECIES(t *testing.T) {
	type args struct {
		pk crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			"success-secp256k1-alice-pointer",
			args{
				func() crypto.PublicKey {
					return secp256k1test.AlicePublicKey.(*secp256k1.PublicKey)
				}(),
			},
			false,
			false,
		},
		{
			"success-secp256k1-alice-val",
			args{
				func() crypto.PublicKey {
					pk := secp256k1test.AlicePublicKey.(*secp256k1.PublicKey)
					return *pk
				}(),
			},
			false,
			false,
		},
		{
			"err-invalid",
			args{
				ed25519test.AlicePublicKey,
			},
			true,
			true,
		},
		{
			"err-invalid-sr25519",
			args{
				sr25519test.BobPublicKey,
			},
			true,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asPublicECIES(tt.args.pk)
			if (err != nil) != tt.wantErr {
				t.Errorf("asPublicECIES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("asPublicECIES() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}
