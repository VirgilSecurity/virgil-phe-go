package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/Scratch-net/PHE/swu"
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

// RandomZ generates big random 256 bit integer which must be less than curve's N parameter
func RandomZ() (z *big.Int) {

	rr := rand.Reader
	rz, err := rand.Int(rr, maxZ)
	if err != nil {
		panic(err)
	}

	for z == nil {
		// If the scalar is out of range, sample another random number.

		if rz.Cmp(curve.Params().N) >= 0 {
			rz, err = rand.Int(rr, maxZ)
			if err != nil {
				panic(err)
			}
		} else {
			z = rz
		}
	}
	return
}

// HashZ maps arrays of bytes to an integer less than curve's N parameter
func HashZ(data ...[]byte) (z *big.Int) {
	if len(data) < 2 {
		panic(data)
	}
	xof := sha3.TupleHashXOF256(data[:len(data)-1], data[len(data)-1])
	rz, err := rand.Int(xof, maxZ)
	if err != nil {
		panic(err)
	}

	for z == nil {
		// If the scalar is out of range, sample another  number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz, err = rand.Int(xof, maxZ)
			if err != nil {
				panic(err)
			}
		} else {
			z = rz
		}
	}
	return
}

// HashToPoint maps arrays of bytes to a valid curve point
func HashToPoint(data ...[]byte) *Point {

	if len(data) < 2 {
		panic(data)
	}

	hash := make([]byte, 32)
	sha3.TupleHash256(data[:len(data)-1], data[len(data)-1], hash)
	x, y := swu.HashToPoint(hash)
	return &Point{x, y}
}
