package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	pwd = []byte("Password")
)

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
	serverKeypair, err := GenerateserverKeypair()
	assert.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	assert.NoError(t, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	assert.NoError(t, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	assert.NoError(t, err)

	// Enroll account

	rec, key, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(t, err)

	//Check password request
	req, err := c.CreateVerifyPasswordRequest(pwd, rec)
	assert.NoError(t, err)
	//Check password on server
	res, err := VerifyPassword(serverKeypair, req)

	assert.NoError(t, err)

	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.Equal(t, key, keyDec)

	//rotation
	token, newPrivate, err := Rotate(serverKeypair)
	assert.NoError(t, err)
	err = c.Rotate(token)
	assert.NoError(t, err)
	//rotated public key must be the same as on server
	newPub, err := GetPublicKey(newPrivate)
	assert.NoError(t, err)
	assert.Equal(t, c.serverPublicKeyBytes, newPub)
	rec1, err := c.Update(rec, token)
	assert.NoError(t, err)
	//Check password request
	req, err = c.CreateVerifyPasswordRequest(pwd, rec1)
	assert.NoError(t, err)
	//Check password on server
	res, err = VerifyPassword(newPrivate, req)
	assert.NoError(t, err)

	//validate response & decrypt M
	keyDec, err = c.CheckResponseAndDecrypt(pwd, rec1, res)
	assert.NoError(t, err)
	// decrypted m must be the same as original
	assert.Equal(t, key, keyDec)

}

func Test_PHE_InvalidPassword(t *testing.T) {
	serverKeypair, err := GenerateserverKeypair()
	assert.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	assert.NoError(t, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	assert.NoError(t, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	assert.NoError(t, err)

	// Enroll account
	rec, _, err := c.EnrollAccount(pwd, enrollment)
	assert.NoError(t, err)

	//Check password request
	req, err := c.CreateVerifyPasswordRequest([]byte("Password1"), rec)
	assert.NoError(t, err)
	//Check password on server
	res, err := VerifyPassword(serverKeypair, req)
	assert.NoError(t, err)
	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt([]byte("Password1"), rec, res)
	assert.Nil(t, err)
	// decrypted m must be nil
	assert.Nil(t, keyDec)
}

func BenchmarkServer_GetEnrollment(b *testing.B) {
	serverKeypair, err := GenerateserverKeypair()
	assert.NoError(b, err)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		GetEnrollment(serverKeypair)
	}
}

func BenchmarkClient_EnrollAccount(b *testing.B) {
	serverKeypair, err := GenerateserverKeypair()
	assert.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	assert.NoError(b, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	assert.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	assert.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := c.EnrollAccount(pwd, enrollment)
		assert.NoError(b, err)
	}
}

func BenchmarkClient_CreateVerifyPasswordRequest(b *testing.B) {
	serverKeypair, err := GenerateserverKeypair()
	assert.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	assert.NoError(b, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	assert.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	assert.NoError(b, err)

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
	serverKeypair, err := GenerateserverKeypair()
	assert.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	assert.NoError(b, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	assert.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	assert.NoError(b, err)

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
		res, err := VerifyPassword(serverKeypair, req)
		assert.NoError(b, err)
		//validate response & decrypt M
		keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
		assert.NoError(b, err)
		// decrypted m must be the same as original
		assert.Equal(b, key, keyDec)
	}
}
