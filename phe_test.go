package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
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
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	require.NoError(t, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(t, err)

	// Enroll account

	rec, key, err := c.EnrollAccount(pwd, enrollment)
	require.NoError(t, err)

	//Check password request
	req, err := c.CreateVerifyPasswordRequest(pwd, rec)
	require.NoError(t, err)
	//Check password on server
	res, err := VerifyPassword(serverKeypair, req)

	require.NoError(t, err)

	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
	require.NoError(t, err)
	// decrypted m must be the same as original
	require.Equal(t, key, keyDec)

	//rotation
	token, newPrivate, err := Rotate(serverKeypair)
	require.NoError(t, err)
	err = c.Rotate(token)
	require.NoError(t, err)
	//rotated public key must be the same as on server
	newPub, err := GetPublicKey(newPrivate)
	require.NoError(t, err)
	require.Equal(t, c.serverPublicKeyBytes, newPub)
	rec1, err := UpdateRecord(rec, token)
	require.NoError(t, err)
	//Check password request
	req, err = c.CreateVerifyPasswordRequest(pwd, rec1)
	require.NoError(t, err)
	//Check password on server
	res, err = VerifyPassword(newPrivate, req)
	require.NoError(t, err)

	//validate response & decrypt M
	keyDec, err = c.CheckResponseAndDecrypt(pwd, rec1, res)
	require.NoError(t, err)
	// decrypted m must be the same as original
	require.Equal(t, key, keyDec)

}

func Test_PHE_InvalidPassword(t *testing.T) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	require.NoError(t, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(t, err)

	// Enroll account
	rec, _, err := c.EnrollAccount(pwd, enrollment)
	require.NoError(t, err)

	//Check password request
	req, err := c.CreateVerifyPasswordRequest([]byte("Password1"), rec)
	require.NoError(t, err)
	//Check password on server
	res, err := VerifyPassword(serverKeypair, req)
	require.NoError(t, err)
	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt([]byte("Password1"), rec, res)
	require.Nil(t, err)
	// decrypted m must be nil
	require.Nil(t, keyDec)
}

func BenchmarkServer_GetEnrollment(b *testing.B) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		GetEnrollment(serverKeypair)
	}
}

func BenchmarkClient_EnrollAccount(b *testing.B) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	require.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := c.EnrollAccount(pwd, enrollment)
		require.NoError(b, err)
	}
}

func BenchmarkClient_CreateVerifyPasswordRequest(b *testing.B) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	require.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(b, err)

	// Enroll account

	rec, _, err := c.EnrollAccount(pwd, enrollment)
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//Check password request
		c.CreateVerifyPasswordRequest(pwd, rec)
	}
}

func BenchmarkLoginFlow(b *testing.B) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(randomZ().Bytes(), pub)
	require.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(b, err)

	// Enroll account

	rec, key, err := c.EnrollAccount(pwd, enrollment)
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//Check password request
		req, err := c.CreateVerifyPasswordRequest(pwd, rec)
		require.NoError(b, err)
		//Check password on server
		res, err := VerifyPassword(serverKeypair, req)
		require.NoError(b, err)
		//validate response & decrypt M
		keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
		require.NoError(b, err)
		// decrypted m must be the same as original
		require.Equal(b, key, keyDec)
	}
}
