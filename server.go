package phe

import (
	"crypto/rand"
	"math/big"
)

type Server struct {
	X *big.Int
}

func (s *Server) GetEnrollment() (ns []byte, c0, c1 *Point, proof *Proof) {
	ns = make([]byte, 32)
	rand.Read(ns)
	hs0, hs1, c0, c1 := s.Eval(ns)
	proof = s.Prove(hs0, hs1, c0, c1)
	return
}

func (s *Server) GetPublicKey() *Point {
	return new(Point).ScalarBaseMult(s.X)
}

func (s *Server) VerifyPassword(ns []byte, c0 *Point) (res bool, c1 *Point, proof *Proof) {
	hs0 := HashToPoint(ns, dhs0)
	hs1 := HashToPoint(ns, dhs1)

	if hs0.ScalarMult(s.X).Equal(c0) {
		res = true
		c1 = hs1.ScalarMult(s.X)
		proof = s.Prove(hs0, hs1, c0, c1)
		gf.FreeInt(hs0.X, hs0.Y, hs1.X, hs1.Y)

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

		// I = (self.X ** a) * (self.G ** b)
		// term1 = c0     ** blind_a
		// term2 = hs0    ** blind_b
		// term3 = self.X ** blind_a
		// term4 = self.G ** blind_b

		I := X.ScalarMult(a).Add(new(Point).ScalarBaseMult(b))

		term1 := c0.ScalarMult(blindA)
		term2 := hs0.ScalarMult(blindB)
		term3 := X.ScalarMult(blindA)
		term4 := new(Point).ScalarBaseMult(blindB)

		pub := new(Point).ScalarBaseMult(s.X)
		challenge := HashZ(pub.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), term4.Marshal(), proofError)

		proof = &Proof{
			Term1: term1,
			Term2: term2,
			Term3: term3,
			Term4: term4,
			Res1:  gf.Add(blindA, gf.Mul(challenge, a)),
			Res2:  gf.Add(blindB, gf.Mul(challenge, b)),
			I:     I,
		}

		gf.FreeInt(hs0.X, hs0.Y, hs1.X, hs1.Y)
		return
	}
}

func (s *Server) Eval(ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = HashToPoint(ns, dhs0)
	hs1 = HashToPoint(ns, dhs1)

	c0 = hs0.ScalarMult(s.X)
	c1 = hs1.ScalarMult(s.X)

	gf.FreeInt(hs0.X, hs0.Y, hs1.X, hs1.Y)
	return
}

func (s *Server) Prove(hs0, hs1, c0, c1 *Point) *Proof {
	blindX := RandomZ()

	term1 := hs0.ScalarMult(blindX)
	term2 := hs1.ScalarMult(blindX)
	term3 := new(Point).ScalarBaseMult(blindX)

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	pub := new(Point).ScalarBaseMult(s.X)
	challenge := HashZ(pub.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), proofOk)
	res := gf.Add(blindX, gf.Mul(challenge, s.X))

	return &Proof{
		Term1: term1,
		Term2: term2,
		Term3: term3,
		Res:   res,
	}

}

func (s *Server) Rotate() (a, b *big.Int, newPub *Point) {
	a, b = RandomZ(), RandomZ()
	s.X = gf.Add(gf.Mul(a, s.X), b)
	newPub = s.GetPublicKey()

	return
}
