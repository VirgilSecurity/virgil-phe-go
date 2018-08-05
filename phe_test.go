package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	l   *Server
	s   *Client
	pwd = []byte("Password")
)

func init() {
	l = &Server{RandomZ()}
	s = &Client{Y: RandomZ()}
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

	//first, ask server for random values & proof
	ns, c0, c1, proof := l.SampleRandomValues()

	// Enroll account

	nc, m, t0, t1, err := s.EnrollAccount(pwd, ns, c0, c1, proof)
	assert.NoError(t, err)

	//Check password request
	c0 = s.CreateVerifyPasswordRequest(nc, pwd, t0)
	//Check password on server
	res, c1, proof := l.VerifyPassword(ns, c0)
	//validate response & decrypt M
	mDec, err := s.CheckResponseAndDecrypt(t0, t1, pwd, ns, nc, c1, proof, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.True(t, m.Equal(mDec))

	//rotation
	a, b := l.Rotate()
	s.Rotate(a)
	t0, t1 = s.Update(t0, t1, ns, a, b)

	//Check password request
	c0 = s.CreateVerifyPasswordRequest(nc, pwd, t0)
	//Check password on server
	res, c1, proof = l.VerifyPassword(ns, c0)
	//validate response & decrypt M
	mDec, err = s.CheckResponseAndDecrypt(t0, t1, pwd, ns, nc, c1, proof, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.True(t, m.Equal(mDec))

}

func Test_PHE_InvalidPassword(t *testing.T) {

	//first, ask server for random values & proof
	ns, c0, c1, proof := l.SampleRandomValues()

	// Enroll account
	nc, _, t0, t1, err := s.EnrollAccount(pwd, ns, c0, c1, proof)
	assert.NoError(t, err)

	//Check password request
	c0 = s.CreateVerifyPasswordRequest(nc, []byte("Password1"), t0)
	//Check password on server
	res, c1, proof := l.VerifyPassword(ns, c0)
	//validate response & decrypt M
	mDec, err := s.CheckResponseAndDecrypt(t0, t1, []byte("Password1"), ns, nc, c1, proof, res)
	assert.Nil(t, err)
	// decrypted m must be nil
	assert.Nil(t, mDec)
}

/*func BenchmarkRateLimiter_Encrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		l.SampleRandomValues()
	}
}

func BenchmarkRateLimiter_Decrypt(b *testing.B) {

	nr, _, _, _ := l.SampleRandomValues()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		l.VerifyPassword(nr)
	}
}

func BenchmarkServer_Encrypt(b *testing.B) {

	_, c0, c1, _ := l.SampleRandomValues()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.EnrollAccount([]byte("Password"), nil, c0, c1, nil)
	}
}

func BenchmarkServer_DecryptStart(b *testing.B) {

	_, c0, c1, _ := l.SampleRandomValues()

	ns, _, t0, t1, _ := s.EnrollAccount([]byte("Password"), nil, c0, c1, nil)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.CreateVerifyPasswordRequest(ns, []byte("Password"), t0, t1)
	}
}

func BenchmarkServer_DecryptEnd(b *testing.B) {

	nr, c0, c1, _ := l.SampleRandomValues()

	ns, _, t0, t1, _ := s.EnrollAccount([]byte("Password"), nil, c0, c1, nil)

	_, t1x := s.CreateVerifyPasswordRequest(ns, []byte("Password"), t0, t1)
	_, c1y, _ := l.VerifyPassword(nr)

	for i := 0; i < b.N; i++ {
		s.VerifyPassword(t1x, c1y)
	}
}*/
