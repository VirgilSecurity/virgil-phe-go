/*
 * Copyright (C) 2015-2026 Virgil Security Inc.
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
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNegBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	require.Equal(t, g.Neg(a), g.NegBytes(a.Bytes()))
}

func TestInvBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	require.Equal(t, g.Inv(a), g.InvBytes(a.Bytes()))
}

func TestAddBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	b := big.NewInt(58)
	require.Equal(t, g.Add(a, b), g.AddBytes(a.Bytes(), b))
}

func TestSub(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(100)
	b := big.NewInt(42)
	result := g.Sub(a, b)
	require.Equal(t, big.NewInt(58), result)

	// Test wrap-around: 0 - 1 should give P-1
	result = g.Sub(big.NewInt(0), big.NewInt(1))
	expected := new(big.Int).Sub(g.P, big.NewInt(1))
	require.Equal(t, expected, result)
}

func TestMulBytes(t *testing.T) {
	g := &GF{P: elliptic.P256().Params().N}
	a := big.NewInt(42)
	b := big.NewInt(58)
	require.Equal(t, g.Mul(a, b), g.MulBytes(a.Bytes(), b))
}
