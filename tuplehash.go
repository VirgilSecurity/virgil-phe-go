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
	"crypto/sha512"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

//TupleHash hashes a slice of byte arrays, prefixing each one with its length
func TupleHash(tuple [][]byte, domain []byte) []byte {
	var sizeBuf [8]byte
	hash := sha512.New512_256()

	for _, t := range tuple {
		writeArray(hash, &sizeBuf, t)
	}
	writeArray(hash, &sizeBuf, domain)
	return hash.Sum(nil)
}

func writeArray(w io.Writer, sizeBuf *[8]byte, a []byte) {
	binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(a)))
	if _, err := w.Write(sizeBuf[:]); err != nil {
		panic(err)
	}
	if _, err := w.Write(a); err != nil {
		panic(err)
	}
}

// TupleKDF creates HKDF instance initialized with TupleHash
func TupleKDF(tuple [][]byte, domain []byte) io.Reader {
	key := TupleHash(tuple, domain)
	return hkdf.New(sha512.New512_256, key, domain, []byte("TupleKDF"))

}
