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

package swu

import (
	"crypto/elliptic"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	c   = elliptic.P256()
	buf = []byte{
		0x80, 0x39, 0x05, 0x35, 0x49, 0x44, 0x70, 0xbe,
		0x0b, 0x29, 0x65, 0x01, 0x58, 0x6b, 0xfc, 0xd9,
		0xe1, 0x31, 0xc3, 0x9e, 0x2d, 0xec, 0xc7, 0x53,
		0xd4, 0xf2, 0x5f, 0xdd, 0xd2, 0x28, 0x1e, 0xe3}
	t = make([]byte, 32)
)

func TestSWU(t *testing.T) {
	h := sha512.Sum512(buf)
	for i := 0; i < 15000; i++ {
		x, y := DataToPoint(h[:])
		require.True(t, elliptic.P256().IsOnCurve(x, y))
		h = sha512.Sum512(h[:])
	}
}

func BenchmarkSWU(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		HashToPoint(buf)
	}
}

func BenchmarkTryInc(b *testing.B) {
	copy(t, buf)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		HashIntoCurvePoint()
		increment(t)
	}
}

func HashIntoCurvePoint() (x, y *big.Int) {
	x, y = tryPoint(t)
	for y == nil || !c.IsOnCurve(x, y) {
		increment(t)
		x, y = tryPoint(t)
	}
	return
}

func tryPoint(r []byte) (x, y *big.Int) {
	x = new(big.Int).SetBytes(r)

	// y² = x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, c.Params().B)

	y = x3.ModSqrt(x3, c.Params().P)
	return
}

func increment(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func TestSWUCompatibility(t *testing.T) {

	data := []byte{
		0x02, 0x6c, 0x68, 0xba, 0x79, 0x9b, 0x95, 0x8d,
		0xa1, 0xdd, 0xec, 0x47, 0xcf, 0x77, 0xb6, 0x1a,
		0x68, 0xe3, 0x27, 0xbb, 0x16, 0xdd, 0x04, 0x6f,
		0x90, 0xfe, 0x2d, 0x7e, 0x46, 0xc7, 0x86, 0x1b,
		0xf9, 0x7a, 0xdb, 0xda, 0x15, 0xef, 0x5c, 0x13,
		0x63, 0xe7, 0x0d, 0x7c, 0xfa, 0x78, 0x24, 0xca,
		0xb9, 0x29, 0x74, 0x96, 0x09, 0x47, 0x15, 0x4d,
		0x34, 0xc4, 0x38, 0xe3, 0xeb, 0xcf, 0xfc, 0xbc,
	}

	x, y := DataToPoint(data)
	require.Equal(t, "41644486759784367771047752285976210905566569374059610763941558650382638987514", x.String())
	require.Equal(t, "47123545766650584118634862924645280635136629360149764686957339607865971771956", y.String())
}
