package phe

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestTupleHash(t *testing.T) {
	tuples := [][]byte{
		{0x00, 0x01, 0x02},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	}
	S := []byte("My Tuple App")
	output := TupleHash(S, tuples...)
	expected := "3696FB515910C43033D7BE0DD1ABFA4F3F8D8354EEC017D41F93A344C9AAB02C006771824DC09C5040BEC8CE9C5FD3833D1301B62750726160098E9A1ED440E4"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestTupleHash: got %s, want %s", got, expected)
	}
}

func TestTupleHashKDF(t *testing.T) {
	outputLength := 64
	tuples := [][]byte{
		{0x00, 0x01, 0x02},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	}
	S := []byte("My Tuple App")
	h := TupleKDF(S, tuples...)
	output := make([]byte, outputLength)
	h.Read(output)
	expected := "B6033704B185DD42053DD77E38F8291175A5425D31BDF659C0297174C547FD23950B5C54422C34BD0D77492B2B4C4CAE514FCA9B65D72F7272086D49FC523F17"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestTupleHashKDF: got %s, want %s", got, expected)
	}
}
