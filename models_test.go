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

	"github.com/stretchr/testify/require"
)

// validPointBytes returns a valid 65-byte curve point for use in tests.
func validPointBytes() []byte {
	return MakePoint().Marshal()
}

func TestEnrollmentRecord_Validate_Nil(t *testing.T) {
	var m *EnrollmentRecord
	_, _, err := m.validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid record")
}

func TestEnrollmentRecord_Validate_BadNonce(t *testing.T) {
	m := &EnrollmentRecord{
		Nc: []byte{1, 2, 3}, // wrong length
		Ns: make([]byte, pheNonceLen),
		T0: validPointBytes(),
		T1: validPointBytes(),
	}
	_, _, err := m.validate()
	require.Error(t, err)

	m2 := &EnrollmentRecord{
		Nc: make([]byte, pheNonceLen),
		Ns: []byte{1, 2, 3}, // wrong length
		T0: validPointBytes(),
		T1: validPointBytes(),
	}
	_, _, err = m2.validate()
	require.Error(t, err)
}

func TestEnrollmentRecord_Validate_BadT0(t *testing.T) {
	m := &EnrollmentRecord{
		Nc: make([]byte, pheNonceLen),
		Ns: make([]byte, pheNonceLen),
		T0: []byte{0x04, 0x01}, // invalid point
		T1: validPointBytes(),
	}
	_, _, err := m.validate()
	require.Error(t, err)
}

func TestEnrollmentRecord_Validate_BadT1(t *testing.T) {
	m := &EnrollmentRecord{
		Nc: make([]byte, pheNonceLen),
		Ns: make([]byte, pheNonceLen),
		T0: validPointBytes(),
		T1: []byte{0x04, 0x01}, // invalid point
	}
	_, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfSuccess_Validate_Nil(t *testing.T) {
	var m *ProofOfSuccess
	_, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfSuccess_Validate_BadTerm1(t *testing.T) {
	m := &ProofOfSuccess{
		Term1:  []byte{0x01},
		Term2:  validPointBytes(),
		Term3:  validPointBytes(),
		BlindX: make([]byte, zLen),
	}
	_, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfSuccess_Validate_BadTerm2(t *testing.T) {
	m := &ProofOfSuccess{
		Term1:  validPointBytes(),
		Term2:  []byte{0x01},
		Term3:  validPointBytes(),
		BlindX: make([]byte, zLen),
	}
	_, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfSuccess_Validate_BadTerm3(t *testing.T) {
	m := &ProofOfSuccess{
		Term1:  validPointBytes(),
		Term2:  validPointBytes(),
		Term3:  []byte{0x01},
		BlindX: make([]byte, zLen),
	}
	_, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfSuccess_Validate_BadBlindX(t *testing.T) {
	m := &ProofOfSuccess{
		Term1:  validPointBytes(),
		Term2:  validPointBytes(),
		Term3:  validPointBytes(),
		BlindX: []byte{0x01, 0x02}, // wrong length
	}
	_, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_Nil(t *testing.T) {
	var m *ProofOfFail
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_BadTerm1(t *testing.T) {
	m := &ProofOfFail{
		Term1:  []byte{0x01},
		Term2:  validPointBytes(),
		Term3:  validPointBytes(),
		Term4:  validPointBytes(),
		BlindA: make([]byte, zLen),
		BlindB: make([]byte, zLen),
	}
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_BadTerm2(t *testing.T) {
	m := &ProofOfFail{
		Term1:  validPointBytes(),
		Term2:  []byte{0x01},
		Term3:  validPointBytes(),
		Term4:  validPointBytes(),
		BlindA: make([]byte, zLen),
		BlindB: make([]byte, zLen),
	}
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_BadTerm3(t *testing.T) {
	m := &ProofOfFail{
		Term1:  validPointBytes(),
		Term2:  validPointBytes(),
		Term3:  []byte{0x01},
		Term4:  validPointBytes(),
		BlindA: make([]byte, zLen),
		BlindB: make([]byte, zLen),
	}
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_BadTerm4(t *testing.T) {
	m := &ProofOfFail{
		Term1:  validPointBytes(),
		Term2:  validPointBytes(),
		Term3:  validPointBytes(),
		Term4:  []byte{0x01},
		BlindA: make([]byte, zLen),
		BlindB: make([]byte, zLen),
	}
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_BadBlindA(t *testing.T) {
	m := &ProofOfFail{
		Term1:  validPointBytes(),
		Term2:  validPointBytes(),
		Term3:  validPointBytes(),
		Term4:  validPointBytes(),
		BlindA: []byte{0x01},
		BlindB: make([]byte, zLen),
	}
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestProofOfFail_Validate_BadBlindB(t *testing.T) {
	m := &ProofOfFail{
		Term1:  validPointBytes(),
		Term2:  validPointBytes(),
		Term3:  validPointBytes(),
		Term4:  validPointBytes(),
		BlindA: make([]byte, zLen),
		BlindB: []byte{0x01},
	}
	_, _, _, _, _, _, err := m.validate()
	require.Error(t, err)
}

func TestUpdateToken_Validate_Nil(t *testing.T) {
	var m *UpdateToken
	_, _, err := m.validate()
	require.Error(t, err)
}

func TestUpdateToken_Validate_BadA(t *testing.T) {
	m := &UpdateToken{
		A: []byte{0x01},
		B: make([]byte, zLen),
	}
	_, _, err := m.validate()
	require.Error(t, err)
}

func TestUpdateToken_Validate_BadB(t *testing.T) {
	m := &UpdateToken{
		A: make([]byte, zLen),
		B: []byte{0x01},
	}
	_, _, err := m.validate()
	require.Error(t, err)
}
