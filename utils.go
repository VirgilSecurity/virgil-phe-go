package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/Scratch-net/SWU"
	"golang.org/x/crypto/sha3"
)

var (
	curve  = elliptic.P256()
	curveG = new(Point).ScalarBaseMult(new(big.Int).SetUint64(1))
	gf     = swu.GF{P: curve.Params().N}
)

type Proof struct {
	Term1, Term2, Term3, Term4, I *Point
	PublicKey                     *Point
	Res                           *big.Int
	Res1, Res2                    *big.Int
}

func RandomZ() (z *big.Int) {
	priv := make([]byte, 32)

	for z == nil {
		io.ReadFull(rand.Reader, priv)

		// If the scalar is out of range, sample another random number.

		if new(big.Int).SetBytes(priv).Cmp(curve.Params().N) >= 0 {
			panic(priv)

		} else {
			z = new(big.Int).SetBytes(priv)
		}
	}
	return
}

func HashZ(data ...[]byte) (z *big.Int) {

	xof := sha3.NewShake256()

	for _, d := range data {
		xof.Write(d)
	}

	h := make([]byte, 32)
	xof.Read(h)

	for z == nil {
		// If the scalar is out of range, sample another  number.
		if new(big.Int).SetBytes(h).Cmp(curve.Params().N) >= 0 {
			xof.Read(h)
		} else {
			z = new(big.Int).SetBytes(h)
		}
	}
	return
}

func HashToPoint(data []byte, extraByte byte) *Point {

	x, y := swu.HashToPoint(append(data, extraByte))
	return &Point{x, y}
}
