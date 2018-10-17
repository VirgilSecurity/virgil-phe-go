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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"github.com/passw0rd/phe-go/swu"

	"github.com/pkg/errors"
)

var (
	curve  = elliptic.P256()
	curveG = new(Point).ScalarBaseMultInt(new(big.Int).SetUint64(1))
	gf     = swu.GF{P: curve.Params().N}
	maxZ   = new(big.Int).SetBit(new(big.Int), 256, 1)

	//domains
	dhc0       = []byte("hc0")
	dhc1       = []byte("hc1")
	dhs0       = []byte("hs0")
	dhs1       = []byte("hs1")
	dm         = []byte("m")
	proofOk    = []byte("ProofOk")
	proofError = []byte("ProofError")
)

// randomZ generates big random 256 bit integer which must be less than curve's N parameter
func randomZ() (z *big.Int) {

	rr := rand.Reader
	rz, err := rand.Int(rr, maxZ)
	if err != nil {
		panic(err)
	}

	for z == nil {
		// If the scalar is out of range, sample another random number.

		if rz.Cmp(curve.Params().N) >= 0 {
			rz, err = rand.Int(rr, maxZ)
			if err != nil {
				panic(err)
			}
		} else {
			z = rz
		}
	}
	return
}

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func hashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof := TupleKDF(data, domain)
	rz, err := rand.Int(xof, maxZ)
	if err != nil {
		panic(err)
	}

	for z == nil {
		// If the scalar is out of range, sample another number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz, err = rand.Int(xof, maxZ)
			if err != nil {
				panic(err)
			}
		} else {
			z = rz
		}
	}
	return
}

// hashToPoint maps arrays of bytes to a valid curve point
func hashToPoint(domain []byte, data ...[]byte) *Point {
	hash := TupleHash(data, domain)
	x, y := swu.HashToPoint(hash)
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
