package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"github.com/Scratch-net/PHE/swu"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

var (
	curve  = elliptic.P256()
	curveG = new(Point).ScalarBaseMultInt(new(big.Int).SetUint64(1))
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

// randomZ generates big random 256 bit integer which must be less than curve's N parameter
func randomZ() (z *big.Int) {

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

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func hashZ(data ...[]byte) (z *big.Int) {
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

// hashToPoint maps arrays of bytes to a valid curve point
func hashToPoint(data ...[]byte) *Point {

	if len(data) < 2 {
		panic(data)
	}

	hash := make([]byte, 32)
	sha3.TupleHash256(data[:len(data)-1], data[len(data)-1], hash)
	x, y := swu.HashToPoint(hash)
	return &Point{x, y}
}

func marshalKeypair(publicKey, privateKey []byte) ([]byte, error) {
	kp := keypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	return asn1.Marshal(kp)
}

func unmarshalKeypair(serverKey []byte) (kp *keypair, err error) {

	kp = &keypair{}
	rest, err := asn1.Unmarshal(serverKey, kp)

	if len(rest) != 0 || err != nil {
		return nil, errors.New("invalid keypair")
	}

	return
}
