package phe

import (
	"crypto/rand"

	"github.com/Scratch-net/SWU"
)

type Server struct {
	PrivateKey []byte
}

func (l *Server) Encrypt(password []byte, c0, c1 *Point) (ns []byte, m, t1, t2 *Point) {
	ns = make([]byte, 32)
	rand.Read(ns)

	mBuf := make([]byte, 32)
	rand.Read(mBuf)
	mx, my := swu.HashToPoint(mBuf)
	m = &Point{mx, my}

	hs0, hs1 := l.Eval(ns, password)

	hs0 = hs0.ScalarMult(l.PrivateKey)
	hs1 = hs1.ScalarMult(l.PrivateKey)
	mEnc := m.ScalarMult(l.PrivateKey)

	t1 = c0.Add(hs0)
	t2 = c1.Add(hs1).Add(mEnc)
	return
}

func (l *Server) Eval(nonce []byte, password []byte) (hs0, hs1 *Point) {
	ns := make([]byte, len(password)+33)
	copy(ns[:len(password)], password)
	copy(ns[len(password):], nonce)

	x, y := swu.HashToPoint(ns)
	hs0 = &Point{x, y}

	ns[len(password)+32] = 1
	x, y = swu.HashToPoint(ns)
	hs1 = &Point{x, y}

	hs0 = hs0.ScalarMult(l.PrivateKey)
	hs1 = hs1.ScalarMult(l.PrivateKey)
	return
}
