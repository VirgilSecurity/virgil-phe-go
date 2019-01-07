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
	"encoding/hex"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	tuples := [][]byte{
		{0x00, 0x01, 0x02},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	}
	S := []byte("My Tuple App")
	output := hash(S, tuples...)
	expected := "3696FB515910C43033D7BE0DD1ABFA4F3F8D8354EEC017D41F93A344C9AAB02C006771824DC09C5040BEC8CE9C5FD3833D1301B62750726160098E9A1ED440E4"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestHash: got %s, want %s", got, expected)
	}
}

func TestKDF(t *testing.T) {
	outputLength := 64
	tuples := [][]byte{
		{0x00, 0x01, 0x02},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	}
	S := []byte("My Tuple App")
	h := initKdf(S, tuples...)
	output := make([]byte, outputLength)
	h.Read(output)
	expected := "0F097707AAB66A4CD5FCC79CEB96FB4B99DE2E73DF09295ECFF6F6CC7C1DCF169D51B62999BC206487800E8DD451518FA6C50F5C053B8B780208BE7164D3A7F2"
	if got := strings.ToUpper(hex.EncodeToString(output)); got != expected {
		t.Errorf("TestKDF: got %s, want %s", got, expected)
	}
}
