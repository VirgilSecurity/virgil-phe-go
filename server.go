package phe

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

// Server is responsible for protecting client records of one website
type Server struct {
	X *big.Int
}

// NewServer instantiates server object with a predefined key
func NewServer(key []byte) (*Server, error) {
	if len(key) > 32 || len(key) == 0 {
		return nil, errors.New("invalid key length")
	}
	return &Server{
		X: new(big.Int).SetBytes(key),
	}, nil
}

// GenerateServer creates new server instance and generates a private key for it
func GenerateServer() (*Server, error) {
	x := RandomZ()
	return NewServer(x.Bytes())
}

// GetEnrollment generates a new random enrollment record and a proof
func (s *Server) GetEnrollment() *EnrollmentResponse {
	ns := make([]byte, 32)
	_, err := rand.Read(ns)
	if err != nil {
		panic(err)
	}
	hs0, hs1, c0, c1 := s.eval(ns)
	proof := s.proveSuccess(hs0, hs1, c0, c1)
	return &EnrollmentResponse{
		NS:    ns,
		C0:    c0.Marshal(),
		C1:    c1.Marshal(),
		Proof: proof,
	}
}

// GetPublicKey returns server public key
func (s *Server) GetPublicKey() []byte {
	return new(Point).ScalarBaseMult(s.X).Marshal()
}

// GetPrivateKey returns server private key
func (s *Server) GetPrivateKey() []byte {
	return s.X.Bytes()
}

// VerifyPassword compares password attempt to the one server would calculate itself using its private key
// and returns a zero knowledge proof of ether success or failure
func (s *Server) VerifyPassword(req *VerifyPasswordRequest) (response *VerifyPasswordResponse, err error) {

	if req == nil || len(req.NS) > 32 || len(req.NS) == 0 {
		err = errors.New("Invalid password verify request")
		return
	}

	ns := req.NS

	c0, err := PointUnmarshal(req.C0)
	if err != nil {
		return
	}

	hs0 := HashToPoint(ns, dhs0)
	hs1 := HashToPoint(ns, dhs1)

	if hs0.ScalarMult(s.X).Equal(c0) {
		//password is ok

		c1 := hs1.ScalarMult(s.X)

		response = &VerifyPasswordResponse{
			Res:          true,
			C1:           c1.Marshal(),
			ProofSuccess: s.proveSuccess(hs0, hs1, c0, c1),
		}
		return
	}

	//password is invalid

	c1, proof := s.proveFailure(c0, hs0)

	response = &VerifyPasswordResponse{
		Res:       false,
		C1:        c1.Marshal(),
		ProofFail: proof,
	}

	return
}

func (s *Server) eval(ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = HashToPoint(ns, dhs0)
	hs1 = HashToPoint(ns, dhs1)

	c0 = hs0.ScalarMult(s.X)
	c1 = hs1.ScalarMult(s.X)
	return
}

func (s *Server) proveSuccess(hs0, hs1, c0, c1 *Point) *ProofOfSuccess {
	blindX := RandomZ()

	term1 := hs0.ScalarMult(blindX)
	term2 := hs1.ScalarMult(blindX)
	term3 := new(Point).ScalarBaseMult(blindX)

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	pub := new(Point).ScalarBaseMult(s.X)
	challenge := HashZ(pub.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), proofOk)
	res := gf.Add(blindX, gf.Mul(challenge, s.X))

	return &ProofOfSuccess{
		Term1:  term1.Marshal(),
		Term2:  term2.Marshal(),
		Term3:  term3.Marshal(),
		BlindX: res.Bytes(),
	}

}

func (s *Server) proveFailure(c0, hs0 *Point) (c1 *Point, proof *ProofOfFail) {
	r := RandomZ()
	minusR := gf.Neg(r)
	minusRX := gf.Mul(minusR, s.X)

	c1 = c0.ScalarMult(r).Add(hs0.ScalarMult(minusRX))

	a := r
	b := minusRX

	blindA := RandomZ()
	blindB := RandomZ()

	X := new(Point).ScalarBaseMult(s.X)

	// I = (self.X ** a) * (self.G ** b)
	// term1 = c0     ** blind_a
	// term2 = hs0    ** blind_b
	// term3 = self.X ** blind_a
	// term4 = self.G ** blind_b

	term1 := c0.ScalarMult(blindA)
	term2 := hs0.ScalarMult(blindB)
	term3 := X.ScalarMult(blindA)
	term4 := new(Point).ScalarBaseMult(blindB)

	pub := new(Point).ScalarBaseMult(s.X)
	challenge := HashZ(pub.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), term4.Marshal(), proofError)

	return c1, &ProofOfFail{
		Term1:  term1.Marshal(),
		Term2:  term2.Marshal(),
		Term3:  term3.Marshal(),
		Term4:  term4.Marshal(),
		BlindA: gf.Add(blindA, gf.Mul(challenge, a)).Bytes(),
		BlindB: gf.Add(blindB, gf.Mul(challenge, b)).Bytes(),
	}
}

//Rotate updates server's private and public keys and issues an update token for use on client's side
func (s *Server) Rotate() (token *UpdateToken, newPrivate []byte) {
	a, b := RandomZ(), RandomZ()
	s.X = gf.Add(gf.Mul(a, s.X), b)
	newPrivate = s.X.Bytes()

	token = &UpdateToken{
		A: a.Bytes(),
		B: b.Bytes(),
	}
	return
}
