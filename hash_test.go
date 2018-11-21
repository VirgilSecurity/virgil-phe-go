package phe

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	tuples := [][]byte{
		{0x00, 0x01, 0x02},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	}
	S := []byte("My Tuple App")
	output := hash(S, tuples...)
	expected := "3696FB515910C43033D7BE0DD1ABFA4F3F8D8354EEC017D41F93A344C9AAB02C006771824DC09C5040BEC8CE9C5FD3833D1301B62750726160098E9A1ED440E4"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestHash: got %s, want %s", got, expected)
	}
}

func TestKDF(t *testing.T) {
	outputLength := 64
	tuples := [][]byte{
		{0x00, 0x01, 0x02},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	}
	S := []byte("My Tuple App")
	h := initKdf(S, tuples...)
	output := make([]byte, outputLength)
	h.Read(output)
	expected := "00F9452A634F68857F650F4BA94AC6F7FD6F350B456FDAD75369C58057B2B6D99F383E3232A4B820DEE3AD4807D9592B9A1003E279209AEB344BEC2B417D7F00"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestKDF: got %s, want %s", got, expected)
	}
}
