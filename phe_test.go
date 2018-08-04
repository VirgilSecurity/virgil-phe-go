package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
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

	ns, c0, c1, proof := l.SampleRandomValues()

	nc, m, t0, t1, err := s.Encrypt([]byte("Password"), ns, c0, c1, proof)
	assert.NoError(t, err)

	c0x, t1x := s.DecryptStart(nc, []byte("Password"), t0, t1)
	c0y, c1y, proof := l.Decrypt(ns)

	assert.Equal(t, c0x, c0y)

	mDec := s.DecryptEnd(t1x, c1y)

	assert.Equal(t, m, mDec)

}

func BenchmarkRateLimiter_Encrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		l.SampleRandomValues()
	}
}

func BenchmarkRateLimiter_Decrypt(b *testing.B) {

	nr, _, _, _ := l.SampleRandomValues()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		l.Decrypt(nr)
	}
}

func BenchmarkServer_Encrypt(b *testing.B) {

	_, c0, c1, _ := l.SampleRandomValues()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.Encrypt([]byte("Password"), nil, c0, c1, nil)
	}
}

func BenchmarkServer_DecryptStart(b *testing.B) {

	_, c0, c1, _ := l.SampleRandomValues()

	ns, _, t0, t1, _ := s.Encrypt([]byte("Password"), nil, c0, c1, nil)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.DecryptStart(ns, []byte("Password"), t0, t1)
	}
}

func BenchmarkServer_DecryptEnd(b *testing.B) {

	nr, c0, c1, _ := l.SampleRandomValues()

	ns, _, t0, t1, _ := s.Encrypt([]byte("Password"), nil, c0, c1, nil)

	_, t1x := s.DecryptStart(ns, []byte("Password"), t0, t1)
	_, c1y, _ := l.Decrypt(nr)

	for i := 0; i < b.N; i++ {
		s.DecryptEnd(t1x, c1y)
	}
}
