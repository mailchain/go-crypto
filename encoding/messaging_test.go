package keys

import (
	"testing"

	"github.com/mailchain/go-encoding"
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519/ed25519test"
	"github.com/mailchain/mailchain/crypto/secp256k1/secp256k1test"
	"github.com/mailchain/mailchain/crypto/sr25519/sr25519test"
	"github.com/stretchr/testify/assert"
)

func TestPrefixMsgKey(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		args args
		len  int
		want string
	}{
		{
			"min-32-bytes-key",
			args{[]byte{
				0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			}},
			33,
			"MsgKey12E6xyuFqQBvKyzJHMa4y6qiEwNw94fosXXr1YA5gVTJkeB",
		},
		{
			"min-plus-one-32-bytes-key",
			args{[]byte{
				0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
			}},
			33,
			"MsgKey12E6xyuFqQBvKyzJHMa4y6qiEwNw94fosXXr1YA5gVTJkeC",
		},
		{
			"mid-32-bytes",
			args{[]byte{
				0x88,
				0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
				0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
				0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
				0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
			}},
			33,
			"MsgKey12vfP2WE4yAKJfJqosQHTc7bJz47uBzipVucRud4efK9byq",
		},
		{
			"max-32-bytes",
			args{[]byte{
				0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			}},
			33,
			"MsgKey13Y9k4nKmqmAQkiKPpWDtYjEkGtuZoQX9bjf3jQRVowWben",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.len, len(tt.args.key))

			assert.Equal(t, tt.want, encoding.EncodeBase58(append(PrefixMsgKey, tt.args.key...)))
		})
	}
}

func TestEncodeMessagingPublicKey(t *testing.T) {
	type args struct {
		key crypto.PublicKey
	}
	tests := []struct {
		name      string
		args      args
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{
			"secp256k1-alice",
			args{
				secp256k1test.AlicePublicKey,
			},
			"",
			assert.Error,
		},
		{
			"secp256k1-bob",
			args{
				secp256k1test.BobPublicKey,
			},
			"",
			assert.Error,
		},
		{
			"ed25519-alice",
			args{
				ed25519test.AlicePublicKey,
			},
			"MsgKey13PNYVnxBhux7pay5k6TBKrhHasBWAavReMXZLJapZfm3je",
			assert.NoError,
		},
		{
			"ed25519-bob",
			args{
				ed25519test.BobPublicKey,
			},
			"MsgKey13PHxtoUBTupmWxMiyDYABwbME5gYSwZhDxBAUYYfeQouDZ",
			assert.NoError,
		},
		{
			"sr25519-alice",
			args{
				sr25519test.AlicePublicKey,
			},
			"MsgKey13PZc7G9tocExwkoMD74B8pgnyetWRoM7cnbAj4y3qHfsxX",
			assert.NoError,
		},
		{
			"sr25519-bob",
			args{
				sr25519test.BobPublicKey,
			},
			"MsgKey13PgzejjbLukR2MKBRJ2LUMsnFojTzxeKqS6jQXVr3yndh9",
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeMessagingPublicKey(tt.args.key)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
