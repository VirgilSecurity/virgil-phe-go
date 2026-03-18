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
