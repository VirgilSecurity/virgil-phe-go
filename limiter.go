package phe

import (
	"crypto/rand"

	"github.com/Scratch-net/SWU"
)

type RateLimiter struct {
	PrivateKey []byte
}

func (l *RateLimiter) Encrypt() (nr []byte, c0, c1 *Point) {
	nr = make([]byte, 32)
	rand.Read(nr)
	c0, c1 = l.Eval(nr)
	return
}

func (l *RateLimiter) Decrypt(nr []byte) (c0, c1 *Point) {
	c0, c1 = l.Eval(nr)
	return
}

func (l *RateLimiter) Eval(nonce []byte) (c0, c1 *Point) {
	nr := make([]byte, 33)
	copy(nr[:32], nonce)

	x, y := swu.HashToPoint(nr)
	c0 = &Point{x, y}

	nr[32] = 1
	x, y = swu.HashToPoint(nr)
	c1 = &Point{x, y}

	c0 = c0.ScalarMult(l.PrivateKey)
	c1 = c1.ScalarMult(l.PrivateKey)
	return
}
