package phe

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type Client struct {
	Y               *big.Int
	ServerPublicKey []byte
}

func (c *Client) EnrollAccount(password []byte, resp *EnrollmentResponse) (rec *EnrollmentRecord, key []byte, err error) {
	nc := make([]byte, 32)
	_, err = rand.Read(nc)
	if err != nil {
		panic(err)
	}

	mBuf := make([]byte, 32)
	_, err = rand.Read(mBuf)
	if err != nil {
		panic(err)
	}
	m := HashToPoint(mBuf, dm)

	kdf := hkdf.New(sha512.New512_256, m.Marshal(), nil, []byte("Secret"))
	key = make([]byte, 32)
	_, err = kdf.Read(key)

	hc0 := HashToPoint(nc, password, dhc0)
	hc1 := HashToPoint(nc, password, dhc1)

	c0, err := PointUnmarshal(resp.C0)
	if err != nil {
		return
	}

	proofValid := c.validateProofOfSuccess(resp.Proof, resp.NS, c0, resp.C1)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	c1, err := PointUnmarshal(resp.C1)
	if err != nil {
		return
	}

	t0 := c0.Add(hc0.ScalarMult(c.Y))
	t1 := c1.Add(hc1.ScalarMult(c.Y)).Add(m.ScalarMult(c.Y))

	rec = &EnrollmentRecord{
		NS: resp.NS,
		NC: nc,
		T0: t0.Marshal(),
		T1: t1.Marshal(),
	}

	return
}

func (c *Client) validateProofOfSuccess(proof *ProofOfSuccess, nonce []byte, c0 *Point, c1b []byte) bool {

	term1, term2, term3, blindX, err := proof.Parse()

	if err != nil {
		return false
	}

	c1, err := PointUnmarshal(c1b)
	if err != nil {
		return false
	}

	hs0 := HashToPoint(nonce, dhs0)
	hs1 := HashToPoint(nonce, dhs1)

	challenge := HashZ(c.ServerPublicKey, curveG.Marshal(), c0.Marshal(), c1b, proof.Term1, proof.Term2, proof.Term3, proofOk)

	//if term1 * (c0 ** challenge) != hs0 ** blind_x:
	// return False

	t1 := term1.Add(c0.ScalarMult(challenge))
	t2 := hs0.ScalarMult(blindX)

	if !t1.Equal(t2) {
		return false
	}

	// if term2 * (c1 ** challenge) != hs1 ** blind_x:
	// return False

	t1 = term2.Add(c1.ScalarMult(challenge))
	t2 = hs1.ScalarMult(blindX)

	if !t1.Equal(t2) {
		return false
	}

	pub, err := PointUnmarshal(c.ServerPublicKey)
	if err != nil {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	// return False

	t1 = term3.Add(pub.ScalarMult(challenge))
	t2 = new(Point).ScalarBaseMult(blindX)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

func (c *Client) CreateVerifyPasswordRequest(password []byte, rec *EnrollmentRecord) (req *VerifyPasswordRequest, err error) {

	if rec == nil || len(rec.NC) == 0 || len(rec.NS) == 0 || len(rec.T0) == 0 {
		return nil, errors.New("invalid client record")
	}

	hc0 := HashToPoint(rec.NC, password, dhc0)
	minusY := gf.Neg(c.Y)

	t0, err := PointUnmarshal(rec.T0)
	if err != nil {
		return nil, errors.New("invalid proof")
	}

	c0 := t0.Add(hc0.ScalarMult(minusY))
	req = &VerifyPasswordRequest{
		C0: c0.Marshal(),
		NS: rec.NS,
	}
	return
}

func (c *Client) CheckResponseAndDecrypt(password []byte, rec *EnrollmentRecord, resp *VerifyPasswordResponse) (key []byte, err error) {

	if resp == nil {
		return nil, errors.New("invalid response")
	}

	t0, t1, err := rec.Parse()
	if err != nil {
		return nil, errors.New("invalid record")
	}

	c1, err := PointUnmarshal(resp.C1)
	if err != nil {
		return nil, err
	}

	hc0 := HashToPoint(rec.NC, password, dhc0)
	hc1 := HashToPoint(rec.NC, password, dhc1)

	hs0 := HashToPoint(rec.NS, dhs0)

	//c0 = t0 * (hc0 ** (-self.y))

	minusY := gf.Neg(c.Y)

	c0 := t0.Add(hc0.ScalarMult(minusY))

	if resp.Res {

		if !c.validateProofOfSuccess(resp.ProofSuccess, rec.NS, c0, resp.C1) {
			return nil, errors.New("result is ok but proof is invalid")
		}

		//return ((t1 * (c1 ** (-1))) *    (hc1 ** (-self.y))) ** (self.y ** (-1))

		m := (t1.Add(c1.Neg()).Add(hc1.ScalarMult(minusY))).ScalarMult(gf.Inv(c.Y))

		kdf := hkdf.New(sha512.New512_256, m.Marshal(), nil, []byte("Secret"))
		key = make([]byte, 32)
		_, err = kdf.Read(key)

		return

	}

	err = c.validateProofOfFail(resp, c0, c1, hs0, hc0, hc1)

	return nil, err
}

func (c *Client) validateProofOfFail(resp *VerifyPasswordResponse, c0, c1, hs0, hc0, hc1 *Point) error {
	term1, term2, term3, term4, blindA, blindB, err := resp.ProofFail.Parse()
	if err != nil {
		return errors.New("invalid public key")
	}

	pub, err := PointUnmarshal(c.ServerPublicKey)
	if err != nil {
		return errors.New("invalid public key")
	}

	challenge := HashZ(c.ServerPublicKey, curveG.Marshal(), c0.Marshal(), resp.C1, resp.ProofFail.Term1, resp.ProofFail.Term2, resp.ProofFail.Term3, resp.ProofFail.Term4, proofError)
	//if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
	//return False
	//
	//if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
	//return False

	t1 := term1.Add(term2).Add(c1.ScalarMult(challenge))
	t2 := c0.ScalarMult(blindA).Add(hs0.ScalarMult(blindB))

	if !t1.Equal(t2) {
		return errors.New("proof verification failed")
	}

	t1 = term3.Add(term4)
	t2 = pub.ScalarMult(blindA).Add(new(Point).ScalarBaseMult(blindB))

	if !t1.Equal(t2) {
		return errors.New("verification failed")
	}
	return nil
}

func (c *Client) Rotate(token *UpdateToken) error {

	if token == nil {
		return errors.New("invalid token")
	}
	if len(token.A) == 0 || len(token.A) > 32 {
		return errors.New("invalid update token")
	}

	if len(token.B) == 0 || len(token.B) > 32 {
		return errors.New("invalid update token")
	}

	a := new(big.Int).SetBytes(token.A)
	b := new(big.Int).SetBytes(token.B)

	c.Y = gf.Mul(c.Y, a)

	pub, err := PointUnmarshal(c.ServerPublicKey)
	if err != nil {
		return errors.New("invalid server public key")
	}
	pub = pub.ScalarMult(a).Add(new(Point).ScalarBaseMult(b))
	c.ServerPublicKey = pub.Marshal()
	return nil
}

func (c *Client) Update(rec *EnrollmentRecord, token *UpdateToken) (updRec *EnrollmentRecord, err error) {

	if token == nil {
		return nil, errors.New("invalid token")
	}
	if len(token.A) == 0 || len(token.A) > 32 {
		return nil, errors.New("invalid update token")
	}

	a := new(big.Int).SetBytes(token.A)

	if len(token.B) == 0 || len(token.B) > 32 {
		return nil, errors.New("invalid update token")
	}

	b := new(big.Int).SetBytes(token.B)

	hs0 := HashToPoint(rec.NS, dhs0)
	hs1 := HashToPoint(rec.NS, dhs1)

	t0, err := PointUnmarshal(rec.T0)
	if err != nil {
		return nil, errors.New("invalid client record")
	}

	t1, err := PointUnmarshal(rec.T1)
	if err != nil {
		return nil, errors.New("invalid client record")
	}

	t00 := t0.ScalarMult(a).Add(hs0.ScalarMult(b))
	t11 := t1.ScalarMult(a).Add(hs1.ScalarMult(b))

	updRec = &EnrollmentRecord{
		T0: t00.Marshal(),
		T1: t11.Marshal(),
		NS: rec.NS,
		NC: rec.NC,
	}
	return
}
