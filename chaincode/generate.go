package chaincode

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"
)

func ChainCodeFromDeriveIndexBytes(input []byte) []byte {
	if len(input) == 32 {
		return input
	}
	if len(input) < 32 {
		// empty padding at the end
		var returnValue = make([]byte, 32)
		copy(returnValue, input)
		return returnValue
	}

	res := blake2b.Sum256(input)
	return res[:]
}

func ChainCodeFromDeriveIndexUint64(input uint64) []byte {
	var bytes [8]byte
	binary.LittleEndian.PutUint64(bytes[:], input)
	return ChainCodeFromDeriveIndexBytes(bytes[:])
}

func ChainCodeFromDeriveIndexString(input string) []byte {
	val := []byte(input)
	len := byte(len(val) << 2) // add bitwise shifted length prefix
	return ChainCodeFromDeriveIndexBytes(append([]byte{len}, val...))
}
