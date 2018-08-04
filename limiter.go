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
	hs0, hs1, c0, c1 := l.Eval(ns)
	proof = l.Prove(hs0, hs1)
	return
}

func (l *RateLimiter) Validate(ns []byte, c0 *Point) (res bool, c1 *Point, proof *Proof) {
	hs0 := GroupHash(ns, 0)
	hs1 := GroupHash(ns, 1)

	if hs0.ScalarMult(l.PrivateKey).Equal(c0) {
		res = true
		c1 = hs1.ScalarMult(l.PrivateKey)
		proof = l.Prove(hs0, hs1)

		return
	} else {

		r := new(big.Int).SetBytes(RandomZ())
		x := new(big.Int).SetBytes(l.PrivateKey)
		f := &swu.GF{P: curve.Params().N}
		minusR := f.Neg(r)

		minusRX := f.Mul(minusR, x)

		c1 = c0.ScalarMult(r.Bytes()).Add(hs0.ScalarMult(minusRX.Bytes()))

		a := r
		b := minusRX

		blindA := new(big.Int).SetBytes(RandomZ())
		blindB := new(big.Int).SetBytes(RandomZ())

		X := new(Point).ScalarBaseMult(l.PrivateKey)

		//					I = (self.X ** a) * (self.G ** b)
		//
		//                term1 = c0     ** blind_a
		//                term2 = hs0    ** blind_b
		//                term3 = self.X ** blind_a
		//                term4 = self.G ** blind_b

		I := X.ScalarMult(a.Bytes()).Add(new(Point).ScalarBaseMult(b.Bytes()))

		term1 := c0.ScalarMult(blindA.Bytes())
		term2 := hs0.ScalarMult(blindB.Bytes())
		term3 := X.ScalarMult(blindA.Bytes())
		term4 := new(Point).ScalarBaseMult(blindB.Bytes())

		buf := append(term1.Marshal(), term2.Marshal()...)
		buf = append(buf, term3.Marshal()...)
		buf = append(buf, term4.Marshal()...)

		challenge := HashZ(buf)
		chlng := new(big.Int).SetBytes(challenge)

		proof = &Proof{
			Term1:     term1,
			Term2:     term2,
			Term3:     term3,
			Term4:     term4,
			Res1:      f.Add(blindA, f.Mul(chlng, a)),
			Res2:      f.Add(blindB, f.Mul(chlng, b)),
			I:         I,
			PublicKey: new(Point).ScalarBaseMult(l.PrivateKey),
		}
		return
	}
}

func (l *RateLimiter) Eval(ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = GroupHash(ns, 0)
	hs1 = GroupHash(ns, 1)

	c0 = hs0.ScalarMult(l.PrivateKey)
	c1 = hs1.ScalarMult(l.PrivateKey)
	return
}

type Proof struct {
	Term1, Term2, Term3, Term4, I *Point
	PublicKey                     *Point
	Res                           *big.Int
	Res1, Res2                    *big.Int
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
