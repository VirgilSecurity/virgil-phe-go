/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

	"github.com/passw0rd/phe-go/swu"

	"github.com/pkg/errors"
)

var (
	curve  = elliptic.P256()
	curveG = new(Point).ScalarBaseMultInt(new(big.Int).SetUint64(1))
	gf     = swu.GF{P: curve.Params().N}

	//domains
	dhc0       = []byte("hc0")
	dhc1       = []byte("hc1")
	dhs0       = []byte("hs0")
	dhs1       = []byte("hs1")
	dm         = []byte("m")
	proofOk    = []byte("ProofOk")
	proofError = []byte("ProofError")
	encrypt    = []byte("PheEncrypt")
)

// randomZ generates big random 256 bit integer which must be less than curve's N parameter
func randomZ() (z *big.Int) {
	rz := makeZ(rand.Reader)
	for z == nil {
		// If the scalar is out of range, sample another random number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(rand.Reader)
		} else {
			z = rz
		}
	}
	return
}

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func hashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof := TupleKDF(domain, data...)
	rz := makeZ(xof)

	for z == nil {
		// If the scalar is out of range, extract another number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(xof)
		} else {
			z = rz
		}
	}
	return
}

func makeZ(reader io.Reader) *big.Int {
	buf := make([]byte, 32)
	_, err := reader.Read(buf)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(buf)
}

// hashToPoint maps arrays of bytes to a valid curve point
func hashToPoint(domain []byte, data ...[]byte) *Point {
	hash := TupleHash(domain, data...)
	x, y := swu.HashToPoint(hash[:32])
	return &Point{x, y}
}

func marshalKeypair(publicKey, privateKey []byte) ([]byte, error) {
	kp := keypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	return asn1.Marshal(kp)
}

func unmarshalKeypair(serverKeypair []byte) (kp *keypair, err error) {

	kp = &keypair{}
	rest, err := asn1.Unmarshal(serverKeypair, kp)

	if len(rest) != 0 || err != nil {
		return nil, errors.New("invalid keypair")
	}

	return
}

// Encrypt generates 32 byte salt, uses master key & salt to generate per-data key & nonce with the help of HKDF
// Salt is concatenated to the ciphertext
func Encrypt(data, key []byte) ([]byte, error) {

	if len(key) != 32 {
		return nil, errors.New("key must be exactly 32 bytes")
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	kdf := hkdf.New(sha512.New, key, salt, encrypt)

	keyNonce := make([]byte, 32+12)
	_, err := kdf.Read(keyNonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:32])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, 32+len(data)+aesGcm.Overhead())
	copy(ct, salt)

	aesGcm.Seal(ct[:32], keyNonce[32:], data, nil)
	return ct, nil
}

// Decrypt extracts 32 byte salt, derives key & nonce and decrypts ciphertext
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be exactly 32 bytes")
	}

	if len(ciphertext) < (32 + 16) {
		return nil, errors.New("invalid ciphertext length")
	}

	salt := ciphertext[:32]
	kdf := hkdf.New(sha512.New, key, salt, encrypt)

	keyNonce := make([]byte, 32+12)
	_, err := kdf.Read(keyNonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:32])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, 0)
	return aesGcm.Open(dst, keyNonce[32:], ciphertext[32:], nil)

}
