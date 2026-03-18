package swu

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNegBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	require.Equal(t, g.Neg(a), g.NegBytes(a.Bytes()))
}

func TestInvBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	require.Equal(t, g.Inv(a), g.InvBytes(a.Bytes()))
}

func TestAddBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	b := big.NewInt(58)
	require.Equal(t, g.Add(a, b), g.AddBytes(a.Bytes(), b))
}

func TestSub(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(100)
	b := big.NewInt(42)
	result := g.Sub(a, b)
	require.Equal(t, big.NewInt(58), result)

	// Test wrap-around: 0 - 1 should give P-1
	result = g.Sub(big.NewInt(0), big.NewInt(1))
	expected := new(big.Int).Sub(g.P, big.NewInt(1))
	require.Equal(t, expected, result)
}

func TestMulBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	b := big.NewInt(58)
	require.Equal(t, g.Mul(a, b), g.MulBytes(a.Bytes(), b))
}
