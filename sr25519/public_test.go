package sr25519

import (
	"testing"

	"github.com/mailchain/go-crypto"
	"github.com/stretchr/testify/assert"
)

func TestPublicKey_Bytes(t *testing.T) {
	tests := []struct {
		name string
		pk   PublicKey
		want []byte
	}{
		{
			"alice",
			alicePublicKey,
			alicePublicKeyBytes,
		},
		{
			"bob",
			bobPublicKey,
			bobPublicKeyBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pk.Bytes(); !assert.Equal(t, tt.want, got) {
				t.Errorf("PublicKey.Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	type args struct {
		keyBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{
			"success-alice-bytes",
			args{
				alicePublicKeyBytes,
			},
			&alicePublicKey,
			false,
		},
		{
			"success-bob-bytes",
			args{
				bobPublicKeyBytes,
			},
			&bobPublicKey,
			false,
		},
		{
			"err-too-short",
			args{
				[]byte{0x72, 0x3c, 0xaa, 0x23},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicKeyFromBytes(tt.args.keyBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKeyFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("PublicKeyFromBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKey_Verify(t *testing.T) {
	tests := []struct {
		name    string
		pk      PublicKey
		message []byte
		sig     []byte
		want    bool
	}{
		{
			"success-bob",
			bobPublicKey,
			[]byte("message"),
			[]byte{0x62, 0x51, 0xaa, 0x51, 0xa4, 0xb4, 0x15, 0xa3, 0xfa, 0x28, 0x86, 0xa4, 0xc6, 0x74, 0xd7, 0x47, 0xf9, 0x1d, 0x27, 0x33, 0xf5, 0xf2, 0x01, 0x00, 0x11, 0x35, 0x1c, 0x7c, 0x79, 0x1a, 0x06, 0x28, 0xca, 0x2d, 0xa1, 0xab, 0xa2, 0x27, 0x34, 0xfe, 0x80, 0x23, 0xe2, 0x9c, 0x87, 0xb6, 0xda, 0xa3, 0x12, 0xf0, 0xc2, 0xef, 0x3e, 0x56, 0x1b, 0xac, 0x48, 0xc6, 0x2a, 0xc5, 0xe6, 0xcd, 0x85, 0x80},
			true,
		},
		{
			"success-alice",
			alicePublicKey,
			[]byte("egassem"),
			[]byte{0x56, 0x61, 0x62, 0x9c, 0x9b, 0x2f, 0xd6, 0xff, 0x80, 0xb4, 0x05, 0x35, 0x5e, 0xf4, 0x12, 0xa5, 0xc5, 0xaa, 0xfe, 0xe4, 0x29, 0x7d, 0x34, 0x11, 0x84, 0x2d, 0xfa, 0x2c, 0x76, 0xbc, 0x1b, 0x74, 0x61, 0x4b, 0xc6, 0x6b, 0xc2, 0x61, 0xa5, 0x65, 0xdc, 0x2b, 0x08, 0x44, 0x64, 0x3b, 0x72, 0xd4, 0x2f, 0xbe, 0xde, 0x7e, 0xc9, 0x80, 0xe3, 0xd9, 0x35, 0x7f, 0x37, 0x0d, 0xd3, 0x42, 0xe7, 0x83},
			true,
		},
		{
			"err-invalid-signature-bob",
			bobPublicKey,
			[]byte("message"),
			[]byte{0xde, 0x6c, 0x88, 0xe6, 0x9c, 0x9f, 0x93, 0xb, 0x59, 0xdd, 0xf4, 0x80, 0xc2, 0x9a, 0x55, 0x79, 0xec, 0x89, 0x5c, 0xa9, 0x7a, 0x36, 0xf6, 0x69, 0x74, 0xc1, 0xf0, 0x15, 0x5c, 0xc0, 0x66, 0x75, 0x2e, 0xcd, 0x9a, 0x9b, 0x41, 0x35, 0xd2, 0x72, 0x32, 0xe0, 0x54, 0x80, 0xbc, 0x98, 0x58, 0x1, 0xa9, 0xfd, 0xe4, 0x27, 0xc7, 0xef, 0xa5, 0x42, 0x5f, 0xf, 0x46, 0x49, 0xb8, 0xad, 0xbd, 0x5},
			false,
		},
		{
			"err-invalid-signature-alice",
			alicePublicKey,
			[]byte("egassem"),
			[]byte{0x7d, 0x51, 0xea, 0xfa, 0x52, 0x78, 0x31, 0x69, 0xd0, 0xa9, 0x4a, 0xc, 0x9f, 0x2b, 0xca, 0xd5, 0xe0, 0x3d, 0x29, 0x17, 0x33, 0x0, 0x93, 0xf, 0xf3, 0xc7, 0xd6, 0x3b, 0xfd, 0x64, 0x17, 0xae, 0x1b, 0xc8, 0x1f, 0xef, 0x51, 0xba, 0x14, 0x9a, 0xe8, 0xa1, 0xe1, 0xda, 0xe0, 0x5f, 0xdc, 0xa5, 0x7, 0x8b, 0x14, 0xba, 0xc4, 0xcf, 0x26, 0xcc, 0xc6, 0x1, 0x1e, 0x5e, 0xab, 0x77, 0x3, 0xc},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pk.Verify(tt.message, tt.sig)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("PublicKey.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
