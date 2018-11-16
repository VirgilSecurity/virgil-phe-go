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
	output := TupleHash(tuples, S)
	expected := "7E873B0765F8F4ED6C82C03BBB1C51FB083F05EF4FF972BD1A8D5FDBFE48C4F2D667321C8CB909570E4C60D387A34E3065CD20352961E703CFCE326DB3C32535"
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
	h := TupleKDF(tuples, S)
	output := make([]byte, outputLength)
	h.Read(output)
	expected := "589FD7CD06D8B8DFC8CF3BAA880C1A4E9D57875D21D56B5A841D97F31BE1AF8DD7FDC249F129B7151C804FFF256096A4CCEA63ED653560D057E4766BD59F7AD8"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestTupleHashKDF: got %s, want %s", got, expected)
	}
}
