package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/Scratch-net/SWU"
)

type RateLimiter struct {
	X *big.Int
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

	if hs0.ScalarMult(l.X).Equal(c0) {
		res = true
		c1 = hs1.ScalarMult(l.X)
		proof = l.Prove(hs0, hs1)

		return
	} else {

		r := RandomZ()
		f := &swu.GF{P: curve.Params().N}
		minusR := f.Neg(r)

		minusRX := f.Mul(minusR, l.X)

		c1 = c0.ScalarMult(r).Add(hs0.ScalarMult(minusRX))

		a := r
		b := minusRX

		blindA := RandomZ()
		blindB := RandomZ()

		X := new(Point).ScalarBaseMult(l.X)

		//					I = (self.X ** a) * (self.G ** b)
		//                term1 = c0     ** blind_a
		//                term2 = hs0    ** blind_b
		//                term3 = self.X ** blind_a
		//                term4 = self.G ** blind_b

		I := X.ScalarMult(a).Add(new(Point).ScalarBaseMult(b))

		term1 := c0.ScalarMult(blindA)
		term2 := hs0.ScalarMult(blindB)
		term3 := X.ScalarMult(blindA)
		term4 := new(Point).ScalarBaseMult(blindB)

		buf := append(term1.Marshal(), term2.Marshal()...)
		buf = append(buf, term3.Marshal()...)
		buf = append(buf, term4.Marshal()...)

		challenge := HashZ(buf)

		proof = &Proof{
			Term1:     term1,
			Term2:     term2,
			Term3:     term3,
			Term4:     term4,
			Res1:      f.Add(blindA, f.Mul(challenge, a)),
			Res2:      f.Add(blindB, f.Mul(challenge, b)),
			I:         I,
			PublicKey: new(Point).ScalarBaseMult(l.X),
		}
		return
	}
}

func (l *RateLimiter) Eval(ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = GroupHash(ns, 0)
	hs1 = GroupHash(ns, 1)

	c0 = hs0.ScalarMult(l.X)
	c1 = hs1.ScalarMult(l.X)
	return
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

	res := gf.Add(blindX, gf.Mul(challenge, l.X))

	return &Proof{
		Term1:     term1,
		Term2:     term2,
		Term3:     term3,
		Res:       res,
		PublicKey: new(Point).ScalarBaseMult(l.X),
	}

}

func (l *RateLimiter) Rotate() (a, b *big.Int) {
	f := swu.GF{P: curve.Params().N}

	a, b = RandomZ(), RandomZ()

	x := l.X
	xa := f.Mul(x, a)
	l.X = f.Add(xa, b)

	return
}
