package phe

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
)

// setupValidEnrollment creates a valid keypair, client, enrollment record, and password for reuse in tests.
func setupValidEnrollment(t *testing.T) (serverKeypair []byte, client *Client, recBytes []byte, password []byte) {
	t.Helper()
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)

	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)

	clientPriv := GenerateClientKey()
	client, err = NewClient(pub, clientPriv)
	require.NoError(t, err)

	enrollResp, err := GetEnrollment(serverKeypair)
	require.NoError(t, err)

	password = []byte("test-password")
	recBytes, _, err = client.EnrollAccount(password, enrollResp)
	require.NoError(t, err)
	return
}

func TestGenerateClientKey(t *testing.T) {
	key := GenerateClientKey()
	require.NotEmpty(t, key)
	require.True(t, len(key) <= 32)
}

func TestNewClient_EmptyPrivateKey(t *testing.T) {
	_, err := NewClient(validPointBytes(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid private key")
}

func TestNewClient_InvalidPublicKey(t *testing.T) {
	_, err := NewClient([]byte{0x01, 0x02}, []byte{0x01})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid public key")
}

func TestEnrollAccount_BadProto(t *testing.T) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(pub, GenerateClientKey())
	require.NoError(t, err)

	_, _, err = c.EnrollAccount([]byte("pwd"), []byte{0xff, 0xff})
	require.Error(t, err)
}

func TestEnrollAccount_BadC0(t *testing.T) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(pub, GenerateClientKey())
	require.NoError(t, err)

	resp := &EnrollmentResponse{
		Ns: make([]byte, pheNonceLen),
		C0: []byte{0x01}, // invalid
		C1: validPointBytes(),
	}
	respBytes, _ := proto.Marshal(resp)
	_, _, err = c.EnrollAccount([]byte("pwd"), respBytes)
	require.Error(t, err)
}

func TestEnrollAccount_BadC1(t *testing.T) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(pub, GenerateClientKey())
	require.NoError(t, err)

	resp := &EnrollmentResponse{
		Ns: make([]byte, pheNonceLen),
		C0: validPointBytes(),
		C1: []byte{0x01}, // invalid
	}
	respBytes, _ := proto.Marshal(resp)
	_, _, err = c.EnrollAccount([]byte("pwd"), respBytes)
	require.Error(t, err)
}

func TestEnrollAccount_BadProof(t *testing.T) {
	serverKeypair, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(serverKeypair)
	require.NoError(t, err)
	c, err := NewClient(pub, GenerateClientKey())
	require.NoError(t, err)

	resp := &EnrollmentResponse{
		Ns:    make([]byte, pheNonceLen),
		C0:    validPointBytes(),
		C1:    validPointBytes(),
		Proof: nil, // no proof
	}
	respBytes, _ := proto.Marshal(resp)
	_, _, err = c.EnrollAccount([]byte("pwd"), respBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid proof")
}

func TestCreateVerifyPasswordRequest_BadProto(t *testing.T) {
	_, c, _, _ := setupValidEnrollment(t)
	_, err := c.CreateVerifyPasswordRequest([]byte("pwd"), []byte{0xff, 0xff})
	require.Error(t, err)
}

func TestCreateVerifyPasswordRequest_EmptyRecord(t *testing.T) {
	_, c, _, _ := setupValidEnrollment(t)
	rec := &EnrollmentRecord{} // empty fields
	recBytes, _ := proto.Marshal(rec)
	_, err := c.CreateVerifyPasswordRequest([]byte("pwd"), recBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client record")
}

func TestCreateVerifyPasswordRequest_BadT0(t *testing.T) {
	_, c, _, _ := setupValidEnrollment(t)
	rec := &EnrollmentRecord{
		Ns: make([]byte, pheNonceLen),
		Nc: make([]byte, pheNonceLen),
		T0: []byte{0x04, 0x01}, // invalid point (not 65 bytes)
		T1: validPointBytes(),
	}
	recBytes, _ := proto.Marshal(rec)
	_, err := c.CreateVerifyPasswordRequest([]byte("pwd"), recBytes)
	require.Error(t, err)
}

func TestCheckResponseAndDecrypt_BadRecProto(t *testing.T) {
	_, c, _, _ := setupValidEnrollment(t)
	_, err := c.CheckResponseAndDecrypt([]byte("pwd"), []byte{0xff}, []byte{0x01})
	require.Error(t, err)
}

func TestCheckResponseAndDecrypt_BadRespProto(t *testing.T) {
	_, c, recBytes, _ := setupValidEnrollment(t)
	_, err := c.CheckResponseAndDecrypt([]byte("pwd"), recBytes, []byte{0xff, 0xff})
	require.Error(t, err)
}

func TestCheckResponseAndDecrypt_BadRecord(t *testing.T) {
	_, c, _, _ := setupValidEnrollment(t)
	badRec := &EnrollmentRecord{
		Ns: []byte{0x01}, // wrong length
		Nc: make([]byte, pheNonceLen),
		T0: validPointBytes(),
		T1: validPointBytes(),
	}
	badRecBytes, _ := proto.Marshal(badRec)
	resp := &VerifyPasswordResponse{Res: true, C1: validPointBytes()}
	respBytes, _ := proto.Marshal(resp)
	_, err := c.CheckResponseAndDecrypt([]byte("pwd"), badRecBytes, respBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid record")
}

func TestCheckResponseAndDecrypt_BadC1(t *testing.T) {
	_, c, recBytes, _ := setupValidEnrollment(t)
	resp := &VerifyPasswordResponse{Res: true, C1: []byte{0x01}}
	respBytes, _ := proto.Marshal(resp)
	_, err := c.CheckResponseAndDecrypt([]byte("pwd"), recBytes, respBytes)
	require.Error(t, err)
}

func TestCheckResponseAndDecrypt_SuccessNilProof(t *testing.T) {
	serverKeypair, c, recBytes, password := setupValidEnrollment(t)

	reqBytes, err := c.CreateVerifyPasswordRequest(password, recBytes)
	require.NoError(t, err)

	// Get a valid response then tamper with it
	respBytes, err := VerifyPassword(serverKeypair, reqBytes)
	require.NoError(t, err)

	resp := &VerifyPasswordResponse{}
	require.NoError(t, proto.Unmarshal(respBytes, resp))
	resp.Proof = nil // remove proof
	tamperedBytes, _ := proto.Marshal(resp)

	_, err = c.CheckResponseAndDecrypt(password, recBytes, tamperedBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof is empty")
}

func TestCheckResponseAndDecrypt_SuccessInvalidProof(t *testing.T) {
	serverKeypair, c, recBytes, password := setupValidEnrollment(t)

	reqBytes, err := c.CreateVerifyPasswordRequest(password, recBytes)
	require.NoError(t, err)

	respBytes, err := VerifyPassword(serverKeypair, reqBytes)
	require.NoError(t, err)

	resp := &VerifyPasswordResponse{}
	require.NoError(t, proto.Unmarshal(respBytes, resp))

	// Tamper with the proof
	proof := resp.GetSuccess()
	require.NotNil(t, proof)
	proof.BlindX = make([]byte, zLen) // zero out blind
	tamperedBytes, _ := proto.Marshal(resp)

	_, err = c.CheckResponseAndDecrypt(password, recBytes, tamperedBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof is invalid")
}

func TestCheckResponseAndDecrypt_FailNilProof(t *testing.T) {
	serverKeypair, c, recBytes, _ := setupValidEnrollment(t)

	// Create request with wrong password to get a failure response
	reqBytes, err := c.CreateVerifyPasswordRequest([]byte("wrong-password"), recBytes)
	require.NoError(t, err)

	respBytes, err := VerifyPassword(serverKeypair, reqBytes)
	require.NoError(t, err)

	resp := &VerifyPasswordResponse{}
	require.NoError(t, proto.Unmarshal(respBytes, resp))
	require.False(t, resp.Res)

	// Remove the fail proof
	resp.Proof = nil
	tamperedBytes, _ := proto.Marshal(resp)

	_, err = c.CheckResponseAndDecrypt([]byte("wrong-password"), recBytes, tamperedBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof is invalid")
}

func TestCheckResponseAndDecrypt_FailInvalidProof(t *testing.T) {
	serverKeypair, c, recBytes, _ := setupValidEnrollment(t)

	reqBytes, err := c.CreateVerifyPasswordRequest([]byte("wrong-password"), recBytes)
	require.NoError(t, err)

	respBytes, err := VerifyPassword(serverKeypair, reqBytes)
	require.NoError(t, err)

	resp := &VerifyPasswordResponse{}
	require.NoError(t, proto.Unmarshal(respBytes, resp))
	require.False(t, resp.Res)

	// Tamper the fail proof
	proof := resp.GetFail()
	require.NotNil(t, proof)
	proof.BlindA = make([]byte, zLen) // zero out
	tamperedBytes, _ := proto.Marshal(resp)

	_, err = c.CheckResponseAndDecrypt([]byte("wrong-password"), recBytes, tamperedBytes)
	require.Error(t, err)
}

func TestValidateProofOfSuccess_SecondCheckFails(t *testing.T) {
	// Get a valid enrollment response with a real proof
	kp, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(kp)
	require.NoError(t, err)
	c, err := NewClient(pub, GenerateClientKey())
	require.NoError(t, err)

	enrollResp, err := GetEnrollment(kp)
	require.NoError(t, err)
	resp := &EnrollmentResponse{}
	require.NoError(t, proto.Unmarshal(enrollResp, resp))

	c0, err := PointUnmarshal(resp.C0)
	require.NoError(t, err)
	c1, err := PointUnmarshal(resp.C1)
	require.NoError(t, err)

	// Sanity: proof is valid with correct parameters
	require.True(t, c.validateProofOfSuccess(resp.Proof, resp.Ns, c0, c1, resp.C0, resp.C1))

	// Pass a different c1 Point but same c1b bytes — challenge stays the same,
	// check 1 passes (uses c0), check 2 fails (uses wrong c1)
	fakeC1 := MakePoint()
	require.False(t, c.validateProofOfSuccess(resp.Proof, resp.Ns, c0, fakeC1, resp.C0, resp.C1))
}

func TestValidateProofOfSuccess_ThirdCheckFails(t *testing.T) {
	kp, err := GenerateServerKeypair()
	require.NoError(t, err)
	pub, err := GetPublicKey(kp)
	require.NoError(t, err)

	enrollResp, err := GetEnrollment(kp)
	require.NoError(t, err)
	resp := &EnrollmentResponse{}
	require.NoError(t, proto.Unmarshal(enrollResp, resp))

	c0, err := PointUnmarshal(resp.C0)
	require.NoError(t, err)
	c1, err := PointUnmarshal(resp.C1)
	require.NoError(t, err)

	// Create a client with a DIFFERENT serverPublicKey Point but same bytes
	// so the challenge is the same but the 3rd check uses the wrong key
	c, err := NewClient(pub, GenerateClientKey())
	require.NoError(t, err)
	c.serverPublicKey = MakePoint() // replace the Point with a random one

	require.False(t, c.validateProofOfSuccess(resp.Proof, resp.Ns, c0, c1, resp.C0, resp.C1))
}

func TestValidateProofOfFail_ValidateError(t *testing.T) {
	serverKeypair, c, recBytes, _ := setupValidEnrollment(t)

	reqBytes, err := c.CreateVerifyPasswordRequest([]byte("wrong-password"), recBytes)
	require.NoError(t, err)

	respBytes, err := VerifyPassword(serverKeypair, reqBytes)
	require.NoError(t, err)

	resp := &VerifyPasswordResponse{}
	require.NoError(t, proto.Unmarshal(respBytes, resp))
	require.False(t, resp.Res)

	// Tamper proof BlindA to wrong length so validate() fails
	proof := resp.GetFail()
	require.NotNil(t, proof)
	proof.BlindA = []byte{0x01} // wrong length
	tamperedBytes, _ := proto.Marshal(resp)

	_, err = c.CheckResponseAndDecrypt([]byte("wrong-password"), recBytes, tamperedBytes)
	require.Error(t, err)
}

func TestValidateProofOfFail_SecondCheckFails(t *testing.T) {
	serverKeypair, c, recBytes, _ := setupValidEnrollment(t)

	reqBytes, err := c.CreateVerifyPasswordRequest([]byte("wrong-password"), recBytes)
	require.NoError(t, err)

	respBytes, err := VerifyPassword(serverKeypair, reqBytes)
	require.NoError(t, err)

	resp := &VerifyPasswordResponse{}
	require.NoError(t, proto.Unmarshal(respBytes, resp))
	require.False(t, resp.Res)

	// Replace client's serverPublicKey with a random point to make the 2nd check fail
	// while the 1st check passes (1st check doesn't use serverPublicKey)
	origPub := c.serverPublicKey
	c.serverPublicKey = MakePoint()

	_, err = c.CheckResponseAndDecrypt([]byte("wrong-password"), recBytes, respBytes)
	require.Error(t, err)
	c.serverPublicKey = origPub
}

func TestRotate_BadToken(t *testing.T) {
	_, c, _, _ := setupValidEnrollment(t)
	err := c.Rotate([]byte{0xff, 0xff})
	require.Error(t, err)
}

func TestUpdateRecord_BadRecProto(t *testing.T) {
	_, err := UpdateRecord([]byte{0xff}, []byte{0xff})
	require.Error(t, err)
}

func TestUpdateRecord_BadTokenProto(t *testing.T) {
	rec := &EnrollmentRecord{
		Ns: make([]byte, pheNonceLen),
		Nc: make([]byte, pheNonceLen),
		T0: validPointBytes(),
		T1: validPointBytes(),
	}
	recBytes, _ := proto.Marshal(rec)
	_, err := UpdateRecord(recBytes, []byte{0xff, 0xff})
	require.Error(t, err)
}

func TestUpdateRecord_BadTokenValidate(t *testing.T) {
	rec := &EnrollmentRecord{
		Ns: make([]byte, pheNonceLen),
		Nc: make([]byte, pheNonceLen),
		T0: validPointBytes(),
		T1: validPointBytes(),
	}
	recBytes, _ := proto.Marshal(rec)
	token := &UpdateToken{A: []byte{0x01}, B: make([]byte, zLen)}
	tokenBytes, _ := proto.Marshal(token)
	_, err := UpdateRecord(recBytes, tokenBytes)
	require.Error(t, err)
}

func TestUpdateRecord_BadRecordValidate(t *testing.T) {
	rec := &EnrollmentRecord{
		Ns: []byte{0x01}, // wrong length
		Nc: make([]byte, pheNonceLen),
		T0: validPointBytes(),
		T1: validPointBytes(),
	}
	recBytes, _ := proto.Marshal(rec)
	token := &UpdateToken{A: make([]byte, zLen), B: make([]byte, zLen)}
	tokenBytes, _ := proto.Marshal(token)
	_, err := UpdateRecord(recBytes, tokenBytes)
	require.Error(t, err)
}

func TestRotateClientKeys_BadTokenProto(t *testing.T) {
	_, _, err := RotateClientKeys(validPointBytes(), []byte{0x01}, []byte{0xff})
	require.Error(t, err)
}

func TestRotateClientKeys_BadTokenValidate(t *testing.T) {
	token := &UpdateToken{A: []byte{0x01}, B: make([]byte, zLen)}
	tokenBytes, _ := proto.Marshal(token)
	_, _, err := RotateClientKeys(validPointBytes(), []byte{0x01}, tokenBytes)
	require.Error(t, err)
}

func TestRotateClientKeys_BadPublicKey(t *testing.T) {
	token := &UpdateToken{A: make([]byte, zLen), B: make([]byte, zLen)}
	tokenBytes, _ := proto.Marshal(token)
	_, _, err := RotateClientKeys([]byte{0x01}, []byte{0x01}, tokenBytes)
	require.Error(t, err)
}

func TestRotateClientKeys_EmptyPrivateKey(t *testing.T) {
	token := &UpdateToken{A: make([]byte, zLen), B: make([]byte, zLen)}
	tokenBytes, _ := proto.Marshal(token)
	_, _, err := RotateClientKeys(validPointBytes(), nil, tokenBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid private key")
}
