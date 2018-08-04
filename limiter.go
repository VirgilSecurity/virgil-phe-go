package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/Scratch-net/SWU"
)

type RateLimiter struct {
	PrivateKey []byte
}

func (l *RateLimiter) SampleRandomValues() (ns []byte, c0, c1 *Point, proof *Proof) {
	ns = make([]byte, 32)
	rand.Read(ns)
	c0, c1, proof = l.Eval(ns)
	return
}

func (l *RateLimiter) Decrypt(nr []byte) (c0, c1 *Point, proof *Proof) {
	c0, c1, proof = l.Eval(nr)

	return
}

func (l *RateLimiter) Eval(nonce []byte) (c0, c1 *Point, proof *Proof) {
	ns := make([]byte, 33)
	copy(ns[:32], nonce)

	x, y := swu.HashToPoint(ns)
	hs0 := &Point{x, y}

	ns[32] = 1
	x, y = swu.HashToPoint(ns)
	hs1 := &Point{x, y}

	c0 = hs0.ScalarMult(l.PrivateKey)
	c1 = hs1.ScalarMult(l.PrivateKey)

	proof = l.Prove(hs0, hs1)

	return
}

type Proof struct {
	Term1, Term2, Term3 *Point
	PublicKey           *Point
	Res                 *big.Int
}

func (l *RateLimiter) Prove(hs0, hs1 *Point) *Proof {
	blindX := RandomZ()

	term1 := hs0.ScalarMult(blindX)
	term2 := hs1.ScalarMult(blindX)
	term3 := new(Point).ScalarBaseMult(blindX)

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	buf := append(term1.Marshal(), term2.Marshal()...)
	buf = append(buf, term3.Marshal()...)

	challenge := HashZ(buf)

	gf := &swu.GF{P: elliptic.P256().Params().N}

	x := new(big.Int).SetBytes(l.PrivateKey)
	chlng := new(big.Int).SetBytes(challenge)
	blind := new(big.Int).SetBytes(blindX)

	res := gf.Add(blind, gf.Mul(chlng, x))

	return &Proof{
		Term1:     term1,
		Term2:     term2,
		Term3:     term3,
		Res:       res,
		PublicKey: new(Point).ScalarBaseMult(l.PrivateKey),
	}

}
