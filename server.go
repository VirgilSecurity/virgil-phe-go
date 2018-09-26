package phe

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

type Server struct {
	X *big.Int
}

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

func (s *Server) GetEnrollment() *Enrollment {
	ns := make([]byte, 32)
	_, err := rand.Read(ns)
	if err != nil {
		panic(err)
	}
	hs0, hs1, c0, c1 := s.eval(ns)
	proof := s.prove(hs0, hs1, c0, c1)
	return &Enrollment{
		NS:    ns,
		C0:    c0.Marshal(),
		C1:    c1.Marshal(),
		Proof: proof,
	}
}

func (s *Server) GetPublicKey() []byte {
	return new(Point).ScalarBaseMult(s.X).Marshal()
}

func (s *Server) GetPrivateKey() []byte {
	return s.X.Bytes()
}

func (s *Server) VerifyPassword(req *VerifyPasswordRequest) (response *VerifyPasswordResponse, err error) {

	if req == nil {
		err = errors.New("Invalid password verify request")
		return
	}

	if len(req.NS) > 32 || len(req.NS) == 0 {
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
			Res:   true,
			C1:    c1.Marshal(),
			Proof: s.prove(hs0, hs1, c0, c1),
		}

		gf.FreeInt(hs0.X, hs0.Y, hs1.X, hs1.Y)

		return
	}

	//password is invalid

	r := RandomZ()
	minusR := gf.Neg(r)
	minusRX := gf.Mul(minusR, s.X)

	c1 := c0.ScalarMult(r).Add(hs0.ScalarMult(minusRX))

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

	response = &VerifyPasswordResponse{
		Res: false,
		C1:  c1.Marshal(),
		Proof: &Proof{
			Term1:  term1.Marshal(),
			Term2:  term2.Marshal(),
			Term3:  term3.Marshal(),
			Term4:  term4.Marshal(),
			BlindA: gf.Add(blindA, gf.Mul(challenge, a)).Bytes(),
			BlindB: gf.Add(blindB, gf.Mul(challenge, b)).Bytes(),
		},
	}

	gf.FreeInt(hs0.X, hs0.Y, hs1.X, hs1.Y)
	return
}

func (s *Server) eval(ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = HashToPoint(ns, dhs0)
	hs1 = HashToPoint(ns, dhs1)

	c0 = hs0.ScalarMult(s.X)
	c1 = hs1.ScalarMult(s.X)

	gf.FreeInt(hs0.X, hs0.Y, hs1.X, hs1.Y)
	return
}

func (s *Server) prove(hs0, hs1, c0, c1 *Point) *Proof {
	blindX := RandomZ()

	term1 := hs0.ScalarMult(blindX)
	term2 := hs1.ScalarMult(blindX)
	term3 := new(Point).ScalarBaseMult(blindX)

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	pub := new(Point).ScalarBaseMult(s.X)
	challenge := HashZ(pub.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), proofOk)
	res := gf.Add(blindX, gf.Mul(challenge, s.X))

	return &Proof{
		Term1:  term1.Marshal(),
		Term2:  term2.Marshal(),
		Term3:  term3.Marshal(),
		BlindX: res.Bytes(),
	}

}

func (s *Server) Rotate() (token *UpdateToken, newPrivate []byte) {
	a, b := RandomZ(), RandomZ()
	s.X = gf.Add(gf.Mul(a, s.X), b)
	newPub := s.GetPublicKey()
	newPrivate = s.X.Bytes()

	token = &UpdateToken{
		A:            a.Bytes(),
		B:            b.Bytes(),
		NewPublicKey: newPub,
	}
	return
}
