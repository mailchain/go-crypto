package ed25519

import (
	"testing"

	"github.com/mailchain/go-encoding/encodingtest"
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/chaincode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveHardenedKey(t *testing.T) {
	type args struct {
		parent crypto.PrivateKey
		path   []uint64
	}
	tests := []struct {
		name string
		args args
		want *PrivateKey
	}{
		{
			"alice://0",
			args{
				&alicePrivateKey,
				[]uint64{0},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0x860feceae0ebccf975cc85092a38ae24e4674e55d3d6aa707a18de71358ccc33"))
				require.NoError(t, err)
				return p
			}(),
		},
		{
			"alice://1",
			args{
				&alicePrivateKey,
				[]uint64{1},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0x729b9cbc57779d707d587e5f860a7cd3db8804ae39f755cd0036fda853da2139"))
				require.NoError(t, err)
				return p
			}(),
		},
		{
			"alice://1//2",
			args{
				&alicePrivateKey,
				[]uint64{1, 2},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0xed9ab0b26b9a3e6d48d55030ba15ec66823fe7d12ca8fad690a8d4bc9b9488cc"))
				require.NoError(t, err)
				return p
			}(),
		},
		{
			"alice://1://2",
			args{
				func() *PrivateKey {
					p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0x729b9cbc57779d707d587e5f860a7cd3db8804ae39f755cd0036fda853da2139"))
					require.NoError(t, err)
					return p
				}(),
				[]uint64{2},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0xed9ab0b26b9a3e6d48d55030ba15ec66823fe7d12ca8fad690a8d4bc9b9488cc"))
				require.NoError(t, err)
				return p
			}(),
		},

		{
			"bob://0",
			args{
				&bobPrivateKey,
				[]uint64{0},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0xccd684257e55f16dd50eea4e52bd04843716e13295a542a143a09792c419191c"))
				require.NoError(t, err)
				return p
			}(),
		},
		{
			"bob://1",
			args{
				&bobPrivateKey,
				[]uint64{1},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0x76f7e8aa3e95bfc13d4ab8b59f6bd82ad3621449fbb66c123cc9c310c7d8d286"))
				require.NoError(t, err)
				return p
			}(),
		},
		{
			"bob://1//2",
			args{
				&bobPrivateKey,
				[]uint64{1, 2},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0xd2c0014e75ccce7b3319f5be5f494e9af56b9596fb7546af0eaef4a9c7caecc3"))
				require.NoError(t, err)
				return p
			}(),
		},
		{
			"bob://1://2",
			args{
				func() *PrivateKey {
					p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0x76f7e8aa3e95bfc13d4ab8b59f6bd82ad3621449fbb66c123cc9c310c7d8d286"))
					require.NoError(t, err)
					return p
				}(),
				[]uint64{2},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0xd2c0014e75ccce7b3319f5be5f494e9af56b9596fb7546af0eaef4a9c7caecc3"))
				require.NoError(t, err)
				return p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parent = tt.args.parent
			var err error
			for _, item := range tt.args.path {

				parent, err = DeriveHardenedKey(parent, chaincode.ChainCodeFromDeriveIndexUint64(item))
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, parent)
		})
	}
}

func TestDeriveHardenedKeyString(t *testing.T) {
	type args struct {
		parent crypto.PrivateKey
		path   []string
	}
	tests := []struct {
		name string
		args args
		want *PrivateKey
	}{
		{
			"bob://1",
			args{
				&bobPrivateKey,
				[]string{"test.string"},
			},
			func() *PrivateKey {
				p, err := PrivateKeyFromBytes(encodingtest.MustDecodeHexZeroX("0x8a4f41889ae03047e2427ec156be5505fa64374007a70aa4ee191c7a76f8e3a4"))
				require.NoError(t, err)
				return p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parent = tt.args.parent
			var err error
			for _, item := range tt.args.path {

				parent, err = DeriveHardenedKey(parent, chaincode.ChainCodeFromDeriveIndexString(item))
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, parent)
		})
	}
}
