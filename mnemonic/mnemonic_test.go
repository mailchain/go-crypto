package mnemonic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToSeed(t *testing.T) {
	type args struct {
		mnemonic string
		password string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"deputy other",
			args{
				"deputy other grain consider empty next inform myself combine dish parent maple priority outdoor inherit lonely battle add humble jar silly tank item balance",
				"",
			},
			[]byte{196, 61, 147, 66, 207, 131, 22, 179, 98, 3, 83, 23, 116, 171, 96, 65, 14, 243, 147, 40, 21, 137, 42, 185, 147, 169, 115, 33, 38, 53, 82, 88},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ToSeed(tt.args.mnemonic, tt.args.password))
		})
	}
}
