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

package phe

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
)

func TestGetEnrollment_BadKeypair(t *testing.T) {
	_, err := GetEnrollment([]byte{0xff, 0xff})
	require.Error(t, err)
}

func TestGetPublicKey_BadKeypair(t *testing.T) {
	_, err := GetPublicKey([]byte{0xff, 0xff})
	require.Error(t, err)
}

func TestVerifyPasswordExtended_BadProto(t *testing.T) {
	kp, err := GenerateServerKeypair()
	require.NoError(t, err)
	_, _, err = VerifyPasswordExtended(kp, []byte{0xff, 0xff})
	require.Error(t, err)
}

func TestVerifyPasswordExtended_BadKeypair(t *testing.T) {
	req := &VerifyPasswordRequest{
		Ns: make([]byte, pheNonceLen),
		C0: validPointBytes(),
	}
	reqBytes, _ := proto.Marshal(req)
	_, _, err := VerifyPasswordExtended([]byte{0xff}, reqBytes)
	require.Error(t, err)
}

func TestVerifyPasswordExtended_BadNonce(t *testing.T) {
	kp, err := GenerateServerKeypair()
	require.NoError(t, err)

	req := &VerifyPasswordRequest{
		Ns: []byte{0x01, 0x02}, // wrong length
		C0: validPointBytes(),
	}
	reqBytes, _ := proto.Marshal(req)
	_, _, err = VerifyPasswordExtended(kp, reqBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid password verify request")
}

func TestVerifyPasswordExtended_BadC0(t *testing.T) {
	kp, err := GenerateServerKeypair()
	require.NoError(t, err)

	req := &VerifyPasswordRequest{
		Ns: make([]byte, pheNonceLen),
		C0: []byte{0x01}, // invalid point
	}
	reqBytes, _ := proto.Marshal(req)
	_, _, err = VerifyPasswordExtended(kp, reqBytes)
	require.Error(t, err)
}

func TestVerifyPasswordExtended_ProveFailureError(t *testing.T) {
	// Craft a keypair with invalid PublicKey bytes but valid PrivateKey
	// so proveFailure's PointUnmarshal(kp.PublicKey) fails
	badKP := &Keypair{
		PublicKey:  []byte{0x04, 0x01}, // invalid point
		PrivateKey: padZ([]byte{0x01}), // non-zero private key
	}
	kpBytes, _ := proto.Marshal(badKP)

	req := &VerifyPasswordRequest{
		Ns: make([]byte, pheNonceLen),
		C0: validPointBytes(), // won't match hs0*sk, so proveFailure is called
	}
	reqBytes, _ := proto.Marshal(req)

	_, _, err := VerifyPasswordExtended(kpBytes, reqBytes)
	require.Error(t, err)
}

func TestServerRotate_BadKeypair(t *testing.T) {
	_, _, err := Rotate([]byte{0xff, 0xff})
	require.Error(t, err)
}
