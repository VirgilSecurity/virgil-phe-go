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

	rec, key, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(t, err)

	//Check password request
	req, err := c.CreateVerifyPasswordRequest(pwd, rec)
	assert.NoError(t, err)
	//Check password on server
	res, err := s.VerifyPassword(req)

	assert.NoError(t, err)

	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.Equal(t, key, keyDec)

	//rotation
	token, _ := s.Rotate()
	err = c.Rotate(token)
	assert.NoError(t, err)
	//rotated public key must be the same as on server
	assert.Equal(t, c.ServerPublicKey, s.GetPublicKey())
	rec1, err := c.Update(rec, token)
	assert.NoError(t, err)
	//Check password request
	req, err = c.CreateVerifyPasswordRequest(pwd, rec1)
	assert.NoError(t, err)
	//Check password on server
	res, err = s.VerifyPassword(req)
	assert.NoError(t, err)

	//validate response & decrypt M
	keyDec, err = c.CheckResponseAndDecrypt(pwd, rec1, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.Equal(t, key, keyDec)

}

func Test_PHE_InvalidPassword(t *testing.T) {

	//first, ask server for random values & proof
	enrollment := s.GetEnrollment()

	// Enroll account
	rec, _, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(t, err)

	//Check password request
	req, err := c.CreateVerifyPasswordRequest([]byte("Password1"), rec)
	assert.NoError(t, err)
	//Check password on server
	res, err := s.VerifyPassword(req)
	assert.NoError(t, err)
	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt([]byte("Password1"), rec, res)
	assert.Nil(t, err)
	// decrypted m must be nil
	assert.Nil(t, keyDec)
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
		_, _, err := c.EnrollAccount(pwd, enrollment)
		assert.NoError(b, err)
	}
}

func BenchmarkClient_CreateVerifyPasswordRequest(b *testing.B) {
	//first, ask server for random values & proof
	enrollment := s.GetEnrollment()

	// Enroll account

	rec, _, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//Check password request
		c.CreateVerifyPasswordRequest(pwd, rec)
	}
}

func BenchmarkLoginFlow(b *testing.B) {

	//first, ask server for random values & proof
	enrollment := s.GetEnrollment()

	// Enroll account

	rec, key, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//Check password request
		req, err := c.CreateVerifyPasswordRequest(pwd, rec)
		assert.NoError(b, err)
		//Check password on server
		res, err := s.VerifyPassword(req)
		assert.NoError(b, err)
		//validate response & decrypt M
		keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
		assert.NoError(b, err)
		// decrypted m must be the same as original
		assert.Equal(b, key, keyDec)
	}
}
