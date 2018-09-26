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

func (c *Client) EnrollAccount(password []byte, enrollment *Enrollment) (rec *ClientRecord, key []byte, err error) {
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

	c0, err := PointUnmarshal(enrollment.C0)
	if err != nil {
		return
	}

	proofValid := c.validateProof(enrollment.Proof, enrollment.NS, c0, enrollment.C1)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	c1, err := PointUnmarshal(enrollment.C1)
	if err != nil {
		return
	}

	t0 := c0.Add(hc0.ScalarMult(c.Y))
	t1 := c1.Add(hc1.ScalarMult(c.Y)).Add(m.ScalarMult(c.Y))

	rec = &ClientRecord{
		NS: enrollment.NS,
		NC: nc,
		T0: t0.Marshal(),
		T1: t1.Marshal(),
	}

	return
}

func (c *Client) validateProof(proof *Proof, nonce []byte, c0 *Point, c1b []byte) bool {

	if proof == nil {
		return false
	}

	term1, err := PointUnmarshal(proof.Term1)
	if err != nil {
		return false
	}

	term2, err := PointUnmarshal(proof.Term2)
	if err != nil {
		return false
	}

	term3, err := PointUnmarshal(proof.Term3)
	if err != nil {
		return false
	}

	c1, err := PointUnmarshal(c1b)
	if err != nil {
		return false
	}

	if len(proof.BlindX) == 0 || len(proof.BlindX) > 32 {
		return false
	}

	blindX := new(big.Int).SetBytes(proof.BlindX)

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

	gf.FreeInt(hs0.X, hs0.Y)
	gf.FreeInt(hs1.X, hs1.Y)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

func (c *Client) CreateVerifyPasswordRequest(password []byte, rec *ClientRecord) (req *VerifyPasswordRequest, err error) {

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
	gf.FreeInt(hc0.X, hc0.Y)

	req = &VerifyPasswordRequest{
		C0: c0.Marshal(),
		NS: rec.NS,
	}
	return
}

func (c *Client) CheckResponseAndDecrypt(password []byte, rec *ClientRecord, res *VerifyPasswordResponse) (key []byte, err error) {

	if res == nil {
		return nil, errors.New("invalid response")
	}

	if rec == nil || len(rec.NC) == 0 || len(rec.NS) == 0 || len(rec.T0) == 0 || len(rec.T1) == 0 {
		return nil, errors.New("invalid client record")
	}

	c1, err := PointUnmarshal(res.C1)
	if err != nil {
		return nil, err
	}

	if res.Proof == nil {
		return nil, errors.New("invalid response")
	}

	hc0 := HashToPoint(rec.NC, password, dhc0)
	hc1 := HashToPoint(rec.NC, password, dhc1)

	hs0 := HashToPoint(rec.NS, dhs0)

	//c0 = t0 * (hc0 ** (-self.y))

	minusY := gf.Neg(c.Y)

	t0, err := PointUnmarshal(rec.T0)
	if err != nil {
		return nil, errors.New("invalid proof")
	}

	t1, err := PointUnmarshal(rec.T1)
	if err != nil {
		return nil, errors.New("invalid proof")
	}

	c0 := t0.Add(hc0.ScalarMult(minusY))

	if res.Res && c.validateProof(res.Proof, rec.NS, c0, res.C1) {
		//return ((t1 * (c1 ** (-1))) *    (hc1 ** (-self.y))) ** (self.y ** (-1))

		m := (t1.Add(c1.Neg()).Add(hc1.ScalarMult(minusY))).ScalarMult(gf.Inv(c.Y))

		kdf := hkdf.New(sha512.New512_256, m.Marshal(), nil, []byte("Secret"))
		key = make([]byte, 32)
		_, err = kdf.Read(key)

		gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)

		return

	}
	{

		term1, err := PointUnmarshal(res.Proof.Term1)
		if err != nil {
			return nil, errors.New("invalid proof")
		}

		term2, err := PointUnmarshal(res.Proof.Term2)
		if err != nil {
			return nil, errors.New("invalid proof")
		}

		term3, err := PointUnmarshal(res.Proof.Term3)
		if err != nil {
			return nil, errors.New("invalid proof")
		}

		term4, err := PointUnmarshal(res.Proof.Term4)
		if err != nil {
			return nil, errors.New("invalid proof")
		}

		pub, err := PointUnmarshal(c.ServerPublicKey)
		if err != nil {
			return nil, errors.New("invalid public key")
		}

		if len(res.Proof.BlindA) == 0 || len(res.Proof.BlindA) > 32 {
			return nil, errors.New("invalid proof")
		}

		if len(res.Proof.BlindB) == 0 || len(res.Proof.BlindB) > 32 {
			return nil, errors.New("invalid proof")
		}

		blindA := new(big.Int).SetBytes(res.Proof.BlindA)
		blindB := new(big.Int).SetBytes(res.Proof.BlindB)

		challenge := HashZ(c.ServerPublicKey, curveG.Marshal(), c0.Marshal(), res.C1, res.Proof.Term1, res.Proof.Term2, res.Proof.Term3, res.Proof.Term4, proofError)
		//if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
		//return False
		//
		//if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
		//return False

		t1 := term1.Add(term2).Add(c1.ScalarMult(challenge))
		t2 := c0.ScalarMult(blindA).Add(hs0.ScalarMult(blindB))

		if !t1.Equal(t2) {
			gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)
			return nil, errors.New("proof verification failed")
		}

		t1 = term3.Add(term4)
		t2 = pub.ScalarMult(blindA).Add(new(Point).ScalarBaseMult(blindB))

		if !t1.Equal(t2) {
			gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)
			return nil, errors.New("verification failed")
		}

	}

	gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)

	return nil, nil
}

func (c *Client) Rotate(token *UpdateToken) error {

	if token == nil {
		return errors.New("invalid token")
	}
	if len(token.A) == 0 || len(token.A) > 32 {
		return errors.New("invalid update token")
	}

	a := new(big.Int).SetBytes(token.A)

	_, err := PointUnmarshal(token.NewPublicKey)
	if err != nil {
		return errors.New("invalid update token")
	}

	c.Y = gf.Mul(c.Y, a)
	c.ServerPublicKey = token.NewPublicKey
	return nil
}

func (c *Client) Update(rec *ClientRecord, token *UpdateToken) (updRec *ClientRecord, err error) {

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

	updRec = &ClientRecord{
		T0: t00.Marshal(),
		T1: t11.Marshal(),
		NS: rec.NS,
		NC: rec.NC,
	}
	return
}
