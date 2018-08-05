package phe

import (
	"crypto/rand"
	"math/big"
)

type Server struct {
	X *big.Int
}

func (s *Server) SampleRandomValues() (ns []byte, c0, c1 *Point, proof *Proof) {
	ns = make([]byte, 32)
	rand.Read(ns)
	hs0, hs1, c0, c1 := s.Eval(ns)
	proof = s.Prove(hs0, hs1)
	return
}

func (s *Server) VerifyPassword(ns []byte, c0 *Point) (res bool, c1 *Point, proof *Proof) {
	hs0 := HashToPoint(ns, 0)
	hs1 := HashToPoint(ns, 1)

	if hs0.ScalarMult(s.X).Equal(c0) {
		res = true
		c1 = hs1.ScalarMult(s.X)
		proof = s.Prove(hs0, hs1)

		return
	} else {

		r := RandomZ()

		minusR := gf.Neg(r)

		minusRX := gf.Mul(minusR, s.X)

		c1 = c0.ScalarMult(r).Add(hs0.ScalarMult(minusRX))

		a := r
		b := minusRX

		blindA := RandomZ()
		blindB := RandomZ()

		X := new(Point).ScalarBaseMult(s.X)

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

		//TODO hash others according to spec
		buf := append(term1.Marshal(), term2.Marshal()...)
		buf = append(buf, term3.Marshal()...)
		buf = append(buf, term4.Marshal()...)

		challenge := HashZ(buf)

		proof = &Proof{
			Term1:     term1,
			Term2:     term2,
			Term3:     term3,
			Term4:     term4,
			Res1:      gf.Add(blindA, gf.Mul(challenge, a)),
			Res2:      gf.Add(blindB, gf.Mul(challenge, b)),
			I:         I,
			PublicKey: new(Point).ScalarBaseMult(s.X),
		}
		return
	}
}

func (s *Server) Eval(ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = HashToPoint(ns, 0)
	hs1 = HashToPoint(ns, 1)

	c0 = hs0.ScalarMult(s.X)
	c1 = hs1.ScalarMult(s.X)
	return
}

func (s *Server) Prove(hs0, hs1 *Point) *Proof {
	blindX := RandomZ()

	term1 := hs0.ScalarMult(blindX)
	term2 := hs1.ScalarMult(blindX)
	term3 := new(Point).ScalarBaseMult(blindX)

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	buf := append(term1.Marshal(), term2.Marshal()...)
	buf = append(buf, term3.Marshal()...)

	challenge := HashZ(buf)

	res := gf.Add(blindX, gf.Mul(challenge, s.X))

	return &Proof{
		Term1:     term1,
		Term2:     term2,
		Term3:     term3,
		Res:       res,
		PublicKey: new(Point).ScalarBaseMult(s.X),
	}

}

func (s *Server) Rotate() (a, b *big.Int) {
	a, b = RandomZ(), RandomZ()

	s.X = gf.Add(gf.Mul(a, s.X), b)

	return
}
