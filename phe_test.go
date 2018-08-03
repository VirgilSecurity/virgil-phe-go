package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/ameteiko/golang-kit/test/assert"
)

var (
	l *RateLimiter
	s *Server
)

func init() {
	skR, _, _, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	skS, _, _, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)

	l = &RateLimiter{skR}
	s = &Server{PrivateKey: skS}
}

func BenchmarkAddP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(p256, rand.Reader)
	_, x1, y1, _ := elliptic.GenerateKey(p256, rand.Reader)

	b.ReportAllocs()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		p256.Add(x, y, x1, y1)
	}

}

func Test_PHE(t *testing.T) {

	nr, c0, c1 := l.Encrypt()

	ns, m, t0, t1 := s.Encrypt([]byte("Password"), c0, c1)

	c0x, t1x := s.DecryptStart(ns, []byte("Password"), t0, t1)
	c0y, c1y := l.Decrypt(nr)

	assert.Equal(t, c0x, c0y)

	mDec := s.DecryptEnd(t1x, c1y)

	assert.Equal(t, m, mDec)

}

func BenchmarkRateLimiter_Encrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		l.Encrypt()
	}
}

func BenchmarkRateLimiter_Decrypt(b *testing.B) {

	nr, _, _ := l.Encrypt()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		l.Decrypt(nr)
	}
}

func BenchmarkServer_Encrypt(b *testing.B) {

	_, c0, c1 := l.Encrypt()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.Encrypt([]byte("Password"), c0, c1)
	}
}

func BenchmarkServer_DecryptStart(b *testing.B) {

	_, c0, c1 := l.Encrypt()

	ns, _, t0, t1 := s.Encrypt([]byte("Password"), c0, c1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.DecryptStart(ns, []byte("Password"), t0, t1)
	}
}

func BenchmarkServer_DecryptEnd(b *testing.B) {

	nr, c0, c1 := l.Encrypt()

	ns, _, t0, t1 := s.Encrypt([]byte("Password"), c0, c1)

	_, t1x := s.DecryptStart(ns, []byte("Password"), t0, t1)
	_, c1y := l.Decrypt(nr)

	for i := 0; i < b.N; i++ {
		s.DecryptEnd(t1x, c1y)
	}
}
