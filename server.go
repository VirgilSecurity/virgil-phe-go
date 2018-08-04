package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/Scratch-net/SWU"
)

type Server struct {
	PrivateKey []byte
	invKey     []byte
}

func (s *Server) Encrypt(password, ns []byte, c0, c1 *Point, proof *Proof) (nc []byte, m, t0, t1 *Point, err error) {
	nc = make([]byte, 32)
	rand.Read(nc)

	mBuf := make([]byte, 32)
	rand.Read(mBuf)
	mx, my := swu.HashToPoint(mBuf)
	m = &Point{mx, my}

	hc0, hc1 := s.Eval(nc, password)

	proofValid := s.ValidateProof(proof, ns, c0, c1)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	hc0 = hc0.ScalarMult(s.PrivateKey)
	hc1 = hc1.ScalarMult(s.PrivateKey)
	mEnc := m.ScalarMult(s.PrivateKey)

	t0 = c0.Add(hc0)
	t1 = c1.Add(hc1).Add(mEnc)
	return
}

func (s *Server) ValidateProof(proof *Proof, nonce []byte, c0, c1 *Point) bool {

	ns := make([]byte, 33)
	copy(ns[:32], nonce)

	x, y := swu.HashToPoint(ns)
	hs0 := &Point{x, y}

	ns[32] = 1
	x, y = swu.HashToPoint(ns)
	hs1 := &Point{x, y}

	buf := append(proof.Term1.Marshal(), proof.Term2.Marshal()...)
	buf = append(buf, proof.Term3.Marshal()...)

	challenge := HashZ(buf)

	//if term1 * (c0 ** challenge) != hs0 ** blind_x:
	//                return False

	t1 := proof.Term1.Add(c0.ScalarMult(challenge))
	t2 := hs0.ScalarMult(proof.Res.Bytes())

	if !t1.Equal(t2) {
		return false
	}

	// if term2 * (c1 ** challenge) != hs1 ** blind_x:
	//                return False

	t1 = proof.Term2.Add(c1.ScalarMult(challenge))
	t2 = hs1.ScalarMult(proof.Res.Bytes())

	if !t1.Equal(t2) {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	//                return False

	t1 = proof.Term3.Add(proof.PublicKey.ScalarMult(challenge))
	t2 = new(Point).ScalarBaseMult(proof.Res.Bytes())

	if !t1.Equal(t2) {
		return false
	}

	return true
}

func (s *Server) DecryptStart(nonce, password []byte, t0, t1 *Point) (c0, t1x *Point) {
	hs0, hs1 := s.Eval(nonce, password)
	hs0 = hs0.ScalarMult(s.PrivateKey)
	hs0.Neg()
	c0 = t0.Add(hs0)

	hs1 = hs1.ScalarMult(s.PrivateKey)
	hs1.Neg()
	t1x = t1.Add(hs1)

	return
}

func (s *Server) DecryptEnd(t1, c1 *Point) (m *Point) {
	c1.Neg()
	mEnc := t1.Add(c1)
	m = mEnc.ScalarMult(s.inverseSk())
	return
}

func (s *Server) inverseSk() []byte {

	if s.invKey == nil {
		sk := new(big.Int).SetBytes(s.PrivateKey)
		skInv := new(big.Int).ModInverse(sk, elliptic.P256().Params().N)
		s.invKey = skInv.Bytes()
	}
	return s.invKey
}

func (s *Server) Eval(nonce []byte, password []byte) (hs0, hs1 *Point) {
	ns := make([]byte, len(password)+33)
	copy(ns[:len(password)], password)
	copy(ns[len(password):], nonce)

	x, y := swu.HashToPoint(ns)
	hs0 = &Point{x, y}

	ns[len(password)+32] = 1
	x, y = swu.HashToPoint(ns)
	hs1 = &Point{x, y}

	hs0 = hs0.ScalarMult(s.PrivateKey)
	hs1 = hs1.ScalarMult(s.PrivateKey)
	return
}
