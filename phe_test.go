package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	s   *Server
	c   *Client
	pwd = []byte("Password")
)

func init() {
	s, _ = GenerateServer()
	c = &Client{Y: RandomZ(), ServerPublicKey: s.GetPublicKey()}
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
	enrollment := s.GetEnrollment()

	// Enroll account

	nc, m, t0, t1, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(t, err)

	//Check password request
	req := c.CreateVerifyPasswordRequest(nc, enrollment.NS, pwd, t0)
	//Check password on server
	res, err := s.VerifyPassword(req)

	assert.NoError(t, err)

	//validate response & decrypt M
	mDec, err := c.CheckResponseAndDecrypt(t0, t1, pwd, enrollment.NS, nc, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.True(t, m.Equal(mDec))

	//rotation
	token, _ := s.Rotate()
	c.Rotate(token)
	t0, t1, err = c.Update(t0, t1, enrollment.NS, token)
	assert.NoError(t, err)
	//Check password request
	req = c.CreateVerifyPasswordRequest(nc, enrollment.NS, pwd, t0)
	//Check password on server
	res, err = s.VerifyPassword(req)
	assert.NoError(t, err)

	//validate response & decrypt M
	mDec, err = c.CheckResponseAndDecrypt(t0, t1, pwd, enrollment.NS, nc, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.True(t, m.Equal(mDec))

}

func Test_PHE_InvalidPassword(t *testing.T) {

	//first, ask server for random values & proof
	enrollment := s.GetEnrollment()

	// Enroll account
	nc, _, t0, t1, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(t, err)

	//Check password request
	req := c.CreateVerifyPasswordRequest(nc, enrollment.NS, []byte("Password1"), t0)
	//Check password on server
	res, err := s.VerifyPassword(req)
	assert.NoError(t, err)
	//validate response & decrypt M
	mDec, err := c.CheckResponseAndDecrypt(t0, t1, []byte("Password1"), enrollment.NS, nc, res)
	assert.Nil(t, err)
	// decrypted m must be nil
	assert.Nil(t, mDec)
}

func BenchmarkServer_GetEnrollment(b *testing.B) {

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.GetEnrollment()
	}
}

func BenchmarkClient_EnrollAccount(b *testing.B) {

	enrollment := s.GetEnrollment()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, _, err := c.EnrollAccount(pwd, enrollment)
		assert.NoError(b, err)
	}
}

func BenchmarkClient_CreateVerifyPasswordRequest(b *testing.B) {
	//first, ask server for random values & proof
	enrollment := s.GetEnrollment()

	// Enroll account

	nc, _, t0, _, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//Check password request
		c.CreateVerifyPasswordRequest(nc, enrollment.NS, pwd, t0)
	}
}

func BenchmarkLoginFlow(b *testing.B) {

	//first, ask server for random values & proof
	enrollment := s.GetEnrollment()

	// Enroll account

	nc, m, t0, t1, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//Check password request
		req := c.CreateVerifyPasswordRequest(nc, enrollment.NS, pwd, t0)
		//Check password on server
		res, err := s.VerifyPassword(req)
		assert.NoError(b, err)
		//validate response & decrypt M
		mDec, err := c.CheckResponseAndDecrypt(t0, t1, pwd, enrollment.NS, nc, res)
		assert.NoError(b, err)
		// decrypted m must be the same as original
		assert.True(b, m.Equal(mDec))
	}
}
