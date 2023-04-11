package secp256r1

import (
	"crypto/ecdsa"
	"io"
	"strings"
	"testing"

	"github.com/mailchain/go-encoding"
	"github.com/mailchain/mailchain/testing/must"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestPrivateKeyFromBytes_Bytes(t *testing.T) {
	type args struct {
		privateKeyBytes []byte
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"alice",
			args{aliceSECP256R1PrivateKeyBytes},
			aliceSECP256R1PrivateKeyBytes,
			assert.NoError,
		},
		{
			"bob",
			args{bobSECP256R1PrivateKeyBytes},
			bobSECP256R1PrivateKeyBytes,
			assert.NoError,
		},
		{
			"carlos",
			args{carlosSECP256R1PrivateKeyBytes},
			carlosSECP256R1PrivateKeyBytes,
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrivateKeyFromBytes(tt.args.privateKeyBytes)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got.Bytes())
		})
	}
}

func TestPrivateKeyFromECDSA_Bytes(t *testing.T) {
	type fields struct {
		privateECDSAKey ecdsa.PrivateKey
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			"alice",
			fields{aliceSECP256R1PrivateECDSA()},
			aliceSECP256R1PrivateKeyBytes,
		},
		{
			"bob",
			fields{bobSECP256R1PrivateECDSA()},
			bobSECP256R1PrivateKeyBytes,
		},
		{
			"carlos",
			fields{carlosSECP256R1PrivateECDSA()},
			carlosSECP256R1PrivateKeyBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PrivateKey{key: tt.fields.privateECDSAKey}
			assert.Equal(t, tt.want, got.Bytes())
		})
	}
}

func TestPrivateKey_PublicKey(t *testing.T) {
	tests := []struct {
		name   string
		target PrivateKey
		want   []byte
	}{
		{
			"alice",
			aliceSECP256R1PrivateKey,
			aliceSECP256R1PublicKeyBytes,
		},
		{
			"bob",
			bobSECP256R1PrivateKey,
			bobSECP256R1PublicKeyBytes,
		},
		{
			"carlos",
			carlosSECP256R1PrivateKey,
			carlosSECP256R1PublicKeyBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.target.PublicKey(); !assert.Equal(t, tt.want, got.Bytes()) {
				t.Errorf("PrivateKey.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_Sign(t *testing.T) {
	// because of MaybeReadByte in /opt/homebrew/Cellar/go@1.18/1.18.9/libexec/src/crypto/internal/randutil/randutil.go which applies a 50% probability to reading an extra byte
	// a zeroReader is required to consistently return the same value or a reader that returns the same bytes each time regardless of the first byte being read or not
	zeroReader := strings.NewReader("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	type fields struct {
		key  ecdsa.PrivateKey
		rand io.Reader
	}
	type args struct {
		message string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"alice",
			fields{
				key:  aliceSECP256R1PrivateECDSA(),
				rand: zeroReader,
			},
			args{
				message: "hello from mailchain",
			},
			[]byte{0xba, 0x16, 0x18, 0xac, 0xa6, 0x3b, 0x24, 0x37, 0x6e, 0x6f, 0x53, 0x8b, 0xee, 0xe4, 0xf7, 0x57, 0x52, 0x30, 0x81, 0x30, 0x6e, 0xd1, 0xf, 0x30, 0x1a, 0xda, 0x1a, 0x59, 0x19, 0xa5, 0xb6, 0x8d, 0x52, 0x6b, 0x2a, 0xe2, 0xf1, 0xcd, 0x8f, 0xd6, 0x98, 0x5c, 0x42, 0xdd, 0xf, 0xe6, 0x81, 0xdc, 0x1d, 0x7e, 0x2e, 0xa0, 0x91, 0xbc, 0xc, 0x2e, 0x52, 0x4d, 0xe6, 0xd6, 0x5f, 0x2c, 0x73, 0x18},
			assert.NoError,
		},
		{
			"bob",
			fields{
				key:  bobSECP256R1PrivateECDSA(),
				rand: zeroReader,
			},
			args{
				message: "hello from mailchain",
			},
			[]byte{0xf3, 0xc5, 0xe4, 0xa9, 0x24, 0xb1, 0x82, 0x64, 0xc1, 0x66, 0xd7, 0x4f, 0x32, 0x10, 0xa1, 0xfb, 0xc4, 0x2d, 0xd4, 0xd9, 0x3b, 0xd, 0x1b, 0xf, 0x6a, 0x96, 0xef, 0x65, 0x84, 0xae, 0x31, 0x90, 0x5d, 0x69, 0x8b, 0xad, 0xee, 0x13, 0x99, 0x28, 0x7f, 0x4c, 0x3f, 0x49, 0xbc, 0xa4, 0xa6, 0x90, 0xa1, 0x9e, 0xf9, 0x5c, 0xe6, 0x20, 0xae, 0xcc, 0x86, 0x2c, 0xc1, 0xe4, 0xf8, 0xd0, 0xcd, 0xf1},
			assert.NoError,
		},
		{
			"carlos",
			fields{
				key:  carlosSECP256R1PrivateECDSA(),
				rand: zeroReader,
			},
			args{
				message: "hello from mailchain",
			},
			[]byte{0xd6, 0xbe, 0x4b, 0x13, 0x41, 0x3f, 0xe3, 0xc1, 0xca, 0x75, 0x62, 0x14, 0xa, 0x52, 0xad, 0x14, 0x46, 0x5f, 0x81, 0xd7, 0xa1, 0xeb, 0xc5, 0xeb, 0x74, 0xe3, 0xe5, 0xef, 0x22, 0x12, 0x6d, 0xfc, 0x25, 0x4, 0x6c, 0x25, 0xad, 0x5a, 0x9, 0xa6, 0x77, 0x54, 0x16, 0x1a, 0xed, 0x35, 0x6a, 0x99, 0xa4, 0xb0, 0x34, 0xe7, 0x1a, 0xec, 0x36, 0xd7, 0x14, 0x19, 0x9c, 0x9e, 0x37, 0x48, 0x5f, 0x56},
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := PrivateKey{
				key:  tt.fields.key,
				rand: tt.fields.rand,
			}
			digest := blake2b.Sum256([]byte(tt.args.message))
			gotSignature, err := pk.Sign(digest[:])
			println(tt.name + ":" + encoding.EncodeHex(gotSignature))
			assert.Equal(t, tt.want, gotSignature)
			tt.assertion(t, err)
		})
	}
}

func TestGenerateKey(t *testing.T) {
	zeroReader := strings.NewReader("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	type args struct {
		rand io.Reader
	}
	tests := []struct {
		name      string
		args      args
		want      *PrivateKey
		assertion assert.ErrorAssertionFunc
	}{
		{
			"zero-reader",
			args{
				zeroReader,
			},
			must.PrivateKey(PrivateKeyFromBytes([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30})).(*PrivateKey),
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKey(tt.args.rand)
			tt.assertion(t, err)
			assert.Equal(t, tt.want.Bytes(), got.Bytes())
		})
	}
}
