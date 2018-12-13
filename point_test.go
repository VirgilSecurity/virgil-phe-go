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
	"testing"

	"github.com/passw0rd/phe-go/swu"

	"github.com/stretchr/testify/assert"
)

func TestPoint_Add_Neg(t *testing.T) {

	p1 := MakePoint()
	p2 := MakePoint()
	p3 := MakePoint()

	p12 := p1.Add(p2)
	p123 := p12.Add(p3)

	p1 = p1.Neg()
	p2 = p2.Neg()

	p123 = p123.Add(p1)
	p123 = p123.Add(p2)

	assert.Equal(t, p3, p123)
}

func MakePoint() *Point {
	b := make([]byte, swu.PointHashLen)
	randRead(b)
	x, y := swu.HashToPoint(b)
	return &Point{x, y}
}

func TestPointUnmarshal(t *testing.T) {
	p1 := MakePoint()

	data := p1.Marshal()

	p2, err := PointUnmarshal(data)
	assert.NoError(t, err)
	assert.True(t, p2.Equal(p1))
}
