package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/ameteiko/golang-kit/test/assert"
)

func Test_PHE(t *testing.T) {

	skR, _, _, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	skS, _, _, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)

	l := &RateLimiter{skR}
	s := &Server{skS}

	nr, c0, c1 := l.Encrypt()

	ns, m, t0, t1 := s.Encrypt([]byte("Password"), c0, c1)

	c0x, t1x := s.DecryptStart(ns, []byte("Password"), t0, t1)
	c0y, c1y := l.Decrypt(nr)

	assert.Equal(t, c0x, c0y)

	mDec := s.DecryptEnd(t1x, c1y)

	assert.Equal(t, m, mDec)

}
