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
	expected := "4C80DEFF221200882FD29CD504BDD745FB8805F3A8C1B295450F033433430BA0B4CE4AFC809D0CD78A015DA33D8C7316CECD577E12DA485BB755730B787DC025"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestKDF: got %s, want %s", got, expected)
	}
}
