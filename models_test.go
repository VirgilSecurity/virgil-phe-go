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
