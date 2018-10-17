package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"github.com/passw0rd/phe-go/swu"

	"github.com/pkg/errors"
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
func hashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof, err := TupleKDF(data, domain)
	if err != nil {
		panic(err)
	}
	rz, err := rand.Int(xof, maxZ)
	if err != nil {
		panic(err)
	}

	for z == nil {
		// If the scalar is out of range, sample another number.
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
func hashToPoint(domain []byte, data ...[]byte) *Point {
	hash, err := TupleHash(data, domain)
	if err != nil {
		panic(err)
	}
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

func unmarshalKeypair(serverKeypair []byte) (kp *keypair, err error) {

	kp = &keypair{}
	rest, err := asn1.Unmarshal(serverKeypair, kp)

	if len(rest) != 0 || err != nil {
		return nil, errors.New("invalid keypair")
	}

	return
}
