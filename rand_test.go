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
	"bytes"
	"crypto/rand"
)

var randBytes = []byte{
	0xfc, 0x9e, 0x1d, 0x89, 0xfa, 0x8b, 0x15, 0xe3,
	0x91, 0xf6, 0x2b, 0x3d, 0xe3, 0x57, 0xb0, 0xf5,
	0x6f, 0xe4, 0xde, 0xc5, 0x4a, 0x00, 0x8c, 0x75,
	0x56, 0xc4, 0x77, 0xbc, 0x96, 0x79, 0xf8, 0x3d,
	0x80, 0x39, 0x05, 0x31, 0x49, 0x44, 0x70, 0xbe,
	0x0b, 0x29, 0x65, 0x01, 0x58, 0x6b, 0xfc, 0xd9,
	0xe1, 0x31, 0xc3, 0x9e, 0x2d, 0xec, 0xc7, 0x53,
	0xd4, 0xf2, 0x5f, 0xef, 0xd2, 0x28, 0x1e, 0xea,
	0xe0, 0x92, 0x7d, 0x0e, 0xd0, 0x57, 0x2e, 0x7f,
	0xe7, 0x7b, 0x60, 0x93, 0x15, 0xbc, 0x86, 0x5e,
	0xd4, 0x38, 0x92, 0xcd, 0x6c, 0xda, 0xf5, 0x65,
	0x18, 0x1a, 0x3d, 0xf9, 0x2b, 0x13, 0x80, 0xdc,
}

func MockRandom() {
	randReader = bytes.NewReader(randBytes)
}

func EndMock() {
	randReader = rand.Reader
}
