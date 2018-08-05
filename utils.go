package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/Scratch-net/SWU"
	"golang.org/x/crypto/sha3"
)

var (
	curve  = elliptic.P256()
	curveG = new(Point).ScalarBaseMult(new(big.Int).SetUint64(1))
	gf     = swu.GF{P: curve.Params().N}
	maxZ   = new(big.Int).SetBit(new(big.Int), 256, 1)
	zero   = []byte{0}
	one    = []byte{1}
)

type Proof struct {
	Term1, Term2, Term3, Term4, I *Point
	PublicKey                     *Point
	Res                           *big.Int
	Res1, Res2                    *big.Int
}

func RandomZ() (z *big.Int) {
	rz, _ := rand.Int(rand.Reader, maxZ)

	for z == nil {
		// If the scalar is out of range, sample another random number.

		if rz.Cmp(curve.Params().N) >= 0 {
			rz, _ = rand.Int(rand.Reader, maxZ)

		} else {
			z = rz
		}
	}
	return
}

func HashZ(data ...[]byte) (z *big.Int) {
	xof := sha3.TupleHashXOF256(data, []byte("HashZ"))
	rz, _ := rand.Int(xof, maxZ)

	for z == nil {
		// If the scalar is out of range, sample another  number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz, _ = rand.Int(xof, maxZ)
		} else {
			z = rz
		}
	}
	return
}

func HashToPoint(data ...[]byte) *Point {
	hash := make([]byte, 32)
	sha3.TupleHash256(data, []byte("HashToPoint"), hash)
	x, y := swu.HashToPoint(hash)
	return &Point{x, y}
}
