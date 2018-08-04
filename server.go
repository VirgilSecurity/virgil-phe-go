package phe

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/Scratch-net/SWU"
)

type Server struct {
	Y *big.Int
}

func (s *Server) Enrollment(password, ns []byte, c0, c1 *Point, proof *Proof) (nc []byte, m, t0, t1 *Point, err error) {
	nc = make([]byte, 32)
	rand.Read(nc)

	mBuf := make([]byte, 32)
	rand.Read(mBuf)
	m = GroupHash(mBuf, 0)

	hc0 := GroupHash(append(nc, password...), 0)
	hc1 := GroupHash(append(nc, password...), 1)

	proofValid := s.ValidateProof(proof, ns, c0, c1)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	t0 = c0.Add(hc0.ScalarMult(s.Y))
	t1 = c1.Add(hc1.ScalarMult(s.Y)).Add(m.ScalarMult(s.Y))
	return
}

func (s *Server) ValidateProof(proof *Proof, nonce []byte, c0, c1 *Point) bool {

	hs0 := GroupHash(nonce, 0)
	hs1 := GroupHash(nonce, 1)

	buf := append(proof.Term1.Marshal(), proof.Term2.Marshal()...)
	buf = append(buf, proof.Term3.Marshal()...)

	challenge := HashZ(buf)

	//if term1 * (c0 ** challenge) != hs0 ** blind_x:
	//                return False

	t1 := proof.Term1.Add(c0.ScalarMult(challenge))
	t2 := hs0.ScalarMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	// if term2 * (c1 ** challenge) != hs1 ** blind_x:
	//                return False

	t1 = proof.Term2.Add(c1.ScalarMult(challenge))
	t2 = hs1.ScalarMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	//                return False

	t1 = proof.Term3.Add(proof.PublicKey.ScalarMult(challenge))
	t2 = new(Point).ScalarBaseMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

func (s *Server) ValidationRequest(nc, password []byte, t0 *Point) (c0 *Point) {
	hc0 := GroupHash(append(nc, password...), 0)
	f := swu.GF{P: curve.Params().N}
	minusY := f.Neg(s.Y)
	c0 = t0.Add(hc0.ScalarMult(minusY))
	return
}

func (s *Server) Validate(t0, t1 *Point, password, ns, nc []byte, c1 *Point, proof *Proof, result bool) (m *Point, err error) {
	hc0 := GroupHash(append(nc, password...), 0)
	hc1 := GroupHash(append(nc, password...), 1)

	hs0 := GroupHash(ns, 0)

	//c0 = t0 * (hc0 ** (-self.y))

	f := swu.GF{P: curve.Params().N}
	minusY := f.Neg(s.Y)

	c0 := t0.Add(hc0.ScalarMult(minusY))

	if result && s.ValidateProof(proof, ns, c0, c1) {
		//return ((t1 * (c1 ** (-1))) *    (hc1 ** (-self.y))) ** (self.y ** (-1))

		f := swu.GF{P: curve.Params().N}
		sInv := f.Inv(s.Y)

		m = (t1.Add(c1.Neg()).Add(hc1.ScalarMult(minusY))).ScalarMult(sInv)
		return

	} else {
		buf := append(proof.Term1.Marshal(), proof.Term2.Marshal()...)
		buf = append(buf, proof.Term3.Marshal()...)
		buf = append(buf, proof.Term4.Marshal()...)

		challenge := HashZ(buf)
		//					if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
		//                    return False
		//
		//                if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
		//                    return False

		t1 := proof.Term1.Add(proof.Term2).Add(c1.ScalarMult(challenge))
		t2 := c0.ScalarMult(proof.Res1).Add(hs0.ScalarMult(proof.Res2))

		if !t1.Equal(t2) {
			return nil, errors.New("verification failed")
		}

		t1 = proof.Term3.Add(proof.Term4).Add(proof.I.ScalarMult(challenge))
		t2 = proof.PublicKey.ScalarMult(proof.Res1).Add(new(Point).ScalarBaseMult(proof.Res2))

		if !t1.Equal(t2) {
			return nil, errors.New("verification failed")
		}

	}

	return nil, nil
}

func (s *Server) Rotate(a *big.Int) {
	f := swu.GF{P: curve.Params().N}
	s.Y = f.Mul(s.Y, a)
}

func (s *Server) Update(t0, t1 *Point, ns []byte, a, b *big.Int) (t00, t11 *Point) {
	hs0 := GroupHash(ns, 0)
	hs1 := GroupHash(ns, 1)

	t00 = t0.ScalarMult(a).Add(hs0.ScalarMult(b))
	t11 = t1.ScalarMult(a).Add(hs1.ScalarMult(b))
	return
}
