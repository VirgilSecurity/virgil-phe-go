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

	//domains
	dhc0       = []byte("hc0")
	dhc1       = []byte("hc1")
	dhs0       = []byte("hs0")
	dhs1       = []byte("hs1")
	dm         = []byte("m")
	proofOk    = []byte("ProofOk")
	proofError = []byte("ProofError")
)

type Proof struct {
	Term1, Term2, Term3, Term4, I *Point
	PublicKey                     *Point
	C1                            *Point
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
	if len(data) < 2 {
		panic(data)
	}
	xof := sha3.TupleHashXOF256(data[:len(data)-1], data[len(data)-1])
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

	if len(data) < 2 {
		panic(data)
	}

	hash := make([]byte, 32)
	sha3.TupleHash256(data[:len(data)-1], data[len(data)-1], hash)
	x, y := swu.HashToPoint(hash)
	return &Point{x, y}
}
