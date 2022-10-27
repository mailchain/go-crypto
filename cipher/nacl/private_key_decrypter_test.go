package nacl

import (
	"bytes"
	"testing"

	"github.com/mailchain/go-encoding/encodingtest"
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/cipher"
	"github.com/mailchain/mailchain/crypto/cipher/ecdh"
	"github.com/mailchain/mailchain/crypto/ed25519/ed25519test"
	"github.com/mailchain/mailchain/crypto/secp256k1/secp256k1test"
	"github.com/mailchain/mailchain/crypto/sr25519/sr25519test"
	"github.com/stretchr/testify/assert"
)

func TestPrivateKeyDecrypter_Decrypt(t *testing.T) {
	type fields struct {
		privateKey  crypto.PrivateKey
		keyExchange cipher.KeyExchange
	}
	type args struct {
		data cipher.EncryptedContent
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      cipher.PlainContent
		assertion assert.ErrorAssertionFunc
	}{
		{
			"secp256k1-alice",
			fields{
				secp256k1test.AlicePrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSECP256K1(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				encodingtest.MustDecodeHex("2be14142434445464748494a4b4c4d4e4f5051525354555657585ff8026ea550c27f5ec06e3ecdfb0850f3352400b7e9e2"),
			},
			[]byte("message"),
			assert.NoError,
		},
		{
			"secp256k1-bob",
			fields{
				secp256k1test.BobPrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSECP256K1(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				encodingtest.MustDecodeHex("2be14142434445464748494a4b4c4d4e4f5051525354555657583abb4c6b03073d8318a8edfa5e3820d761b9d07682e179"),
			},
			[]byte("message"),
			assert.NoError,
		},
		{
			"ed25519-alice",
			fields{
				ed25519test.AlicePrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewED25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				encodingtest.MustDecodeHex("2be24142434445464748494a4b4c4d4e4f505152535455565758ede31931c34d9e1d251cf6466b1d628957a55bcce73486"),
			},
			[]byte("message"),
			assert.NoError,
		},
		{
			"ed25519-bob",
			fields{
				ed25519test.BobPrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewED25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				encodingtest.MustDecodeHex("2be24142434445464748494a4b4c4d4e4f5051525354555657581a7d53c9fc1d9b4103f7e9c234f5897688cc68dbadbe17"),
			},
			[]byte("message"),
			assert.NoError,
		},
		{
			"sr25519-alice",
			fields{
				sr25519test.AlicePrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSR25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				encodingtest.MustDecodeHex("2be24142434445464748494a4b4c4d4e4f505152535455565758ede31931c34d9e1d251cf6466b1d628957a55bcce73486"),
			},
			nil,
			assert.Error,
		},
		{
			"sr25519-bob",
			fields{
				sr25519test.BobPrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSR25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				encodingtest.MustDecodeHex("2be24142434445464748494a4b4c4d4e4f5051525354555657581a7d53c9fc1d9b4103f7e9c234f5897688cc68dbadbe17"),
			},
			nil,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := PrivateKeyDecrypter{
				privateKey:  tt.fields.privateKey,
				keyExchange: tt.fields.keyExchange,
			}
			got, err := d.Decrypt(tt.args.data)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
