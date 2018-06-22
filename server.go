package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/Scratch-net/SWU"
)

type Server struct {
	PrivateKey []byte
	invKey     []byte
}

func (l *Server) Encrypt(password []byte, c0, c1 *Point) (ns []byte, m, t0, t1 *Point) {
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

	t0 = c0.Add(hs0)
	t1 = c1.Add(hs1).Add(mEnc)
	return
}

func (l *Server) DecryptStart(nonce, password []byte, t0, t1 *Point) (c0, t1x *Point) {
	hs0, hs1 := l.Eval(nonce, password)
	hs0 = hs0.ScalarMult(l.PrivateKey)
	hs0.Neg()
	c0 = t0.Add(hs0)

	hs1 = hs1.ScalarMult(l.PrivateKey)
	hs1.Neg()
	t1x = t1.Add(hs1)

	return
}

func (l *Server) DecryptEnd(t1, c1 *Point) (m *Point) {
	c1.Neg()
	mEnc := t1.Add(c1)
	m = mEnc.ScalarMult(l.inverseSk())
	return
}

func (l *Server) inverseSk() []byte {

	if l.invKey == nil {
		sk := new(big.Int).SetBytes(l.PrivateKey)
		skInv := fermatInverse(sk, elliptic.P256().Params().N)
		l.invKey = skInv.Bytes()
	}
	return l.invKey
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
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
