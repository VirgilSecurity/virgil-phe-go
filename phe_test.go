/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package phe

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	pwd = []byte("Password")
)

func BenchmarkAddP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(p256, randReader)
	_, x1, y1, _ := elliptic.GenerateKey(p256, randReader)

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
	c, err := NewClient(pub, randomZ().Bytes())
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
	resp, result1, err := VerifyPasswordExtended(serverKeypair, req)

	require.NoError(t, err)
	require.True(t, result1.Res)

	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, resp)
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
	resp, result2, err := VerifyPasswordExtended(newPrivate, req)
	require.NoError(t, err)
	require.Equal(t, result1.Salt, result2.Salt)
	require.True(t, result2.Res)

	//validate response & decrypt M
	keyDec, err = c.CheckResponseAndDecrypt(pwd, rec1, resp)
	require.NoError(t, err)
	// decrypted m must be the same as original
	require.Equal(t, key, keyDec)

}

func Test_PHE_InvalidPassword(t *testing.T) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(pub, randomZ().Bytes())
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
	resp, result, err := VerifyPasswordExtended(serverKeypair, req)
	require.NoError(t, err)
	require.False(t, result.Res)
	//validate response & decrypt M
	keyDec, err := c.CheckResponseAndDecrypt([]byte("Password1"), rec, resp)
	require.Nil(t, err)
	// decrypted m must be nil
	require.Nil(t, keyDec)
}

func BenchmarkServer_GetEnrollment(b *testing.B) {
	MockRandom()
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		MockRandom()
		GetEnrollment(serverKeypair)
	}
}

func BenchmarkClient_EnrollAccount(b *testing.B) {
	MockRandom()
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(pub, randomZ().Bytes())
	require.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		MockRandom()
		_, _, err := c.EnrollAccount(pwd, enrollment)
		require.NoError(b, err)
	}
}

func BenchmarkClient_CreateVerifyPasswordRequest(b *testing.B) {
	MockRandom()
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(pub, randomZ().Bytes())
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

func BenchmarkVerifyDecrypt(b *testing.B) {
	MockRandom()
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(pub, randomZ().Bytes())
	require.NoError(b, err)

	//first, ask server for random values & proof
	enrollment, err := GetEnrollment(serverKeypair)
	require.NoError(b, err)

	// Enroll account

	rec, key, err := c.EnrollAccount(pwd, enrollment)
	require.NoError(b, err)
	//Check password request
	req, err := c.CreateVerifyPasswordRequest(pwd, rec)
	require.NoError(b, err)
	//Check password on server
	res, err := VerifyPassword(serverKeypair, req)
	require.NoError(b, err)
	//validate response & decrypt M
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {

		keyDec, err := c.CheckResponseAndDecrypt(pwd, rec, res)
		require.NoError(b, err)
		// decrypted m must be the same as original
		require.Equal(b, key, keyDec)
	}
	EndMock()
}

func BenchmarkLoginFlow(b *testing.B) {
	MockRandom()
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(b, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(b, err)
	c, err := NewClient(pub, randomZ().Bytes())
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
		MockRandom()
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
