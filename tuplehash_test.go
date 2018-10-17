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
	expected := "BA3CA6BD5B2AEDCD8D139E9EC75672392095FB8698CD46B434ACC3911769D103"
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
	expected := "3E203E1D240016FAB77BB4C5B71B24F324D9E9656A859B07E9B09E57B08EEF6E911EDEB8A392C9161100DC3EEEA63398077AD1DD6FA5511451515D1ED07708EB"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestTupleHashKDF: got %s, want %s", got, expected)
	}
}
