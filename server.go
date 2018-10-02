package phe

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

// GenerateServerKey creates a new random Nist p-256 keypair
func GenerateServerKey() ([]byte, error) {
	privateKey := randomZ().Bytes()
	publicKey := new(Point).ScalarBaseMult(privateKey)

	return marshalKeypair(publicKey.Marshal(), privateKey)

}

// GetEnrollment generates a new random enrollment record and a proof
func GetEnrollment(serverKey []byte) (*EnrollmentResponse, error) {

	kp, err := unmarshalKeypair(serverKey)
	if err != nil {
		return nil, err
	}

	ns := make([]byte, 32)
	_, err = rand.Read(ns)
	if err != nil {
		return nil, err
	}
	hs0, hs1, c0, c1 := eval(kp, ns)
	proof := proveSuccess(kp, hs0, hs1, c0, c1)
	return &EnrollmentResponse{
		NS:    ns,
		C0:    c0.Marshal(),
		C1:    c1.Marshal(),
		Proof: proof,
	}, nil
}

// GetPublicKey returns server public key
func GetPublicKey(serverKey []byte) ([]byte, error) {
	key, err := unmarshalKeypair(serverKey)
	if err != nil {
		return nil, err
	}

	return key.PublicKey, nil
}

// VerifyPassword compares password attempt to the one server would calculate itself using its private key
// and returns a zero knowledge proof of ether success or failure
func VerifyPassword(serverKey []byte, req *VerifyPasswordRequest) (response *VerifyPasswordResponse, err error) {

	kp, err := unmarshalKeypair(serverKey)
	if err != nil {
		return nil, err
	}

	if req == nil || len(req.NS) > 32 || len(req.NS) == 0 {
		err = errors.New("Invalid password verify request")
		return
	}

	ns := req.NS

	c0, err := PointUnmarshal(req.C0)
	if err != nil {
		return
	}

	hs0 := hashToPoint(ns, dhs0)
	hs1 := hashToPoint(ns, dhs1)

	if hs0.ScalarMult(kp.PrivateKey).Equal(c0) {
		//password is ok

		c1 := hs1.ScalarMult(kp.PrivateKey)

		response = &VerifyPasswordResponse{
			Res:          true,
			C1:           c1.Marshal(),
			ProofSuccess: proveSuccess(kp, hs0, hs1, c0, c1),
		}
		return
	}

	//password is invalid

	c1, proof, err := proveFailure(kp, c0, hs0)
	if err != nil {
		return
	}

	response = &VerifyPasswordResponse{
		Res:       false,
		C1:        c1.Marshal(),
		ProofFail: proof,
	}

	return
}

func eval(kp *keypair, ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = hashToPoint(ns, dhs0)
	hs1 = hashToPoint(ns, dhs1)

	c0 = hs0.ScalarMult(kp.PrivateKey)
	c1 = hs1.ScalarMult(kp.PrivateKey)
	return
}

func proveSuccess(kp *keypair, hs0, hs1, c0, c1 *Point) *ProofOfSuccess {
	blindX := randomZ()

	term1 := hs0.ScalarMult(blindX.Bytes())
	term2 := hs1.ScalarMult(blindX.Bytes())
	term3 := new(Point).ScalarBaseMult(blindX.Bytes())

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	challenge := hashZ(kp.PublicKey, curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), proofOk)
	res := gf.Add(blindX, gf.MulBytes(kp.PrivateKey, challenge))

	return &ProofOfSuccess{
		Term1:  term1.Marshal(),
		Term2:  term2.Marshal(),
		Term3:  term3.Marshal(),
		BlindX: res.Bytes(),
	}

}

func proveFailure(kp *keypair, c0, hs0 *Point) (c1 *Point, proof *ProofOfFail, err error) {
	r := randomZ()
	minusR := gf.Neg(r)
	minusRX := gf.MulBytes(kp.PrivateKey, minusR)

	c1 = c0.ScalarMult(r.Bytes()).Add(hs0.ScalarMult(minusRX.Bytes()))

	a := r
	b := minusRX

	blindA := randomZ().Bytes()
	blindB := randomZ().Bytes()

	publicKey, err := PointUnmarshal(kp.PublicKey)
	if err != nil {
		return
	}

	// I = (self.X ** a) * (self.G ** b)
	// term1 = c0     ** blind_a
	// term2 = hs0    ** blind_b
	// term3 = self.X ** blind_a
	// term4 = self.G ** blind_b

	term1 := c0.ScalarMult(blindA)
	term2 := hs0.ScalarMult(blindB)
	term3 := publicKey.ScalarMult(blindA)
	term4 := new(Point).ScalarBaseMult(blindB)

	challenge := hashZ(kp.PublicKey, curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), term4.Marshal(), proofError)

	return c1, &ProofOfFail{
		Term1:  term1.Marshal(),
		Term2:  term2.Marshal(),
		Term3:  term3.Marshal(),
		Term4:  term4.Marshal(),
		BlindA: gf.AddBytes(blindA, gf.Mul(challenge, a)).Bytes(),
		BlindB: gf.AddBytes(blindB, gf.Mul(challenge, b)).Bytes(),
	}, nil
}

//Rotate updates server's private and public keys and issues an update token for use on client's side
func Rotate(serverKey []byte) (token *UpdateToken, newServerKey []byte, err error) {

	kp, err := unmarshalKeypair(serverKey)
	if err != nil {
		return
	}
	a, b := randomZ(), randomZ()
	newPrivate := gf.Add(gf.MulBytes(kp.PrivateKey, a), b).Bytes()
	newPublic := new(Point).ScalarBaseMult(newPrivate)

	newServerKey, err = marshalKeypair(newPublic.Marshal(), newPrivate)
	if err != nil {
		return
	}

	token = &UpdateToken{
		A: a.Bytes(),
		B: b.Bytes(),
	}

	return
}
