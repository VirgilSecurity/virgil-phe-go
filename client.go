package phe

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// Client is responsible for protecting & checking passwords at the client (website) side
type Client struct {
	Y               *big.Int
	ServerPublicKey []byte
}

// EnrollAccount uses fresh Enrollment Response and user's password (or its hash) to create a new Enrollment Record which
// is then supposed to be stored in a database
// it also generates a random encryption key which can be used to protect user's data
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

	t0 := c0.Add(hc0.ScalarMultInt(c.Y))
	t1 := c1.Add(hc1.ScalarMultInt(c.Y)).Add(m.ScalarMultInt(c.Y))

	rec = &EnrollmentRecord{
		NS: resp.NS,
		NC: nc,
		T0: t0.Marshal(),
		T1: t1.Marshal(),
	}

	return
}

func (c *Client) validateProofOfSuccess(proof *ProofOfSuccess, nonce []byte, c0 *Point, c1b []byte) bool {

	term1, term2, term3, blindX, err := proof.parse()

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

	t1 := term1.Add(c0.ScalarMultInt(challenge))
	t2 := hs0.ScalarMultInt(blindX)

	if !t1.Equal(t2) {
		return false
	}

	// if term2 * (c1 ** challenge) != hs1 ** blind_x:
	// return False

	t1 = term2.Add(c1.ScalarMultInt(challenge))
	t2 = hs1.ScalarMultInt(blindX)

	if !t1.Equal(t2) {
		return false
	}

	pub, err := PointUnmarshal(c.ServerPublicKey)
	if err != nil {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	// return False

	t1 = term3.Add(pub.ScalarMultInt(challenge))
	t2 = new(Point).ScalarBaseMultInt(blindX)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

//CreateVerifyPasswordRequest creates a request in a form of elliptic curve point which is then need to be validated at the server side
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

	c0 := t0.Add(hc0.ScalarMultInt(minusY))
	req = &VerifyPasswordRequest{
		C0: c0.Marshal(),
		NS: rec.NS,
	}
	return
}

// CheckResponseAndDecrypt verifies server's answer and extracts data encryption key on success
func (c *Client) CheckResponseAndDecrypt(password []byte, rec *EnrollmentRecord, resp *VerifyPasswordResponse) (key []byte, err error) {

	if resp == nil {
		return nil, errors.New("invalid response")
	}

	t0, t1, err := rec.parse()
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

	c0 := t0.Add(hc0.ScalarMultInt(minusY))

	if resp.Res {

		if !c.validateProofOfSuccess(resp.ProofSuccess, rec.NS, c0, resp.C1) {
			return nil, errors.New("result is ok but proof is invalid")
		}

		//return ((t1 * (c1 ** (-1))) *    (hc1 ** (-self.y))) ** (self.y ** (-1))

		m := (t1.Add(c1.Neg()).Add(hc1.ScalarMultInt(minusY))).ScalarMultInt(gf.Inv(c.Y))

		kdf := hkdf.New(sha512.New512_256, m.Marshal(), nil, []byte("Secret"))
		key = make([]byte, 32)
		_, err = kdf.Read(key)

		return

	}

	err = c.validateProofOfFail(resp, c0, c1, hs0, hc0, hc1)

	return nil, err
}

func (c *Client) validateProofOfFail(resp *VerifyPasswordResponse, c0, c1, hs0, hc0, hc1 *Point) error {
	term1, term2, term3, term4, blindA, blindB, err := resp.ProofFail.parse()
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

	t1 := term1.Add(term2).Add(c1.ScalarMultInt(challenge))
	t2 := c0.ScalarMultInt(blindA).Add(hs0.ScalarMultInt(blindB))

	if !t1.Equal(t2) {
		return errors.New("proof verification failed")
	}

	t1 = term3.Add(term4)
	t2 = pub.ScalarMultInt(blindA).Add(new(Point).ScalarBaseMultInt(blindB))

	if !t1.Equal(t2) {
		return errors.New("verification failed")
	}
	return nil
}

// Rotate updates client's secret key and server's public key with server's update token
func (c *Client) Rotate(token *UpdateToken) error {

	a, b, err := token.parse()
	if err != nil {
		return err
	}

	c.Y = gf.Mul(c.Y, a)

	pub, err := PointUnmarshal(c.ServerPublicKey)
	if err != nil {
		return errors.New("invalid server public key")
	}
	pub = pub.ScalarMultInt(a).Add(new(Point).ScalarBaseMultInt(b))
	c.ServerPublicKey = pub.Marshal()
	return nil
}

// Update needs to be applied to every database record to correspond to new private and public keys
func (c *Client) Update(rec *EnrollmentRecord, token *UpdateToken) (updRec *EnrollmentRecord, err error) {

	a, b, err := token.parse()
	if err != nil {
		return nil, err
	}

	t0, t1, err := rec.parse()
	if err != nil {
		return nil, err
	}

	hs0 := HashToPoint(rec.NS, dhs0)
	hs1 := HashToPoint(rec.NS, dhs1)

	t00 := t0.ScalarMultInt(a).Add(hs0.ScalarMultInt(b))
	t11 := t1.ScalarMultInt(a).Add(hs1.ScalarMultInt(b))

	updRec = &EnrollmentRecord{
		T0: t00.Marshal(),
		T1: t11.Marshal(),
		NS: rec.NS,
		NC: rec.NC,
	}
	return
}
