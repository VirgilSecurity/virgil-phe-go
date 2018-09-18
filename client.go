package phe

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Client struct {
	Y               *big.Int
	ServerPublicKey *Point
}

func (c *Client) EnrollAccount(password, ns []byte, c0, c1 *Point, proof *Proof) (nc []byte, m, t0, t1 *Point, err error) {
	nc = make([]byte, 32)
	rand.Read(nc)

	mBuf := make([]byte, 32)
	rand.Read(mBuf)
	m = HashToPoint(mBuf, dm)

	hc0 := HashToPoint(nc, password, dhc0)
	hc1 := HashToPoint(nc, password, dhc1)

	proofValid := c.ValidateProof(proof, ns, c0, c1)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	t0 = c0.Add(hc0.ScalarMult(c.Y))
	t1 = c1.Add(hc1.ScalarMult(c.Y)).Add(m.ScalarMult(c.Y))
	return
}

func (c *Client) ValidateProof(proof *Proof, nonce []byte, c0, c1 *Point) bool {

	hs0 := HashToPoint(nonce, dhs0)
	hs1 := HashToPoint(nonce, dhs1)

	challenge := HashZ(c.ServerPublicKey.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), proof.Term1.Marshal(), proof.Term2.Marshal(), proof.Term3.Marshal(), proofOk)

	//if term1 * (c0 ** challenge) != hs0 ** blind_x:
	// return False

	t1 := proof.Term1.Add(c0.ScalarMult(challenge))
	t2 := hs0.ScalarMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	// if term2 * (c1 ** challenge) != hs1 ** blind_x:
	// return False

	t1 = proof.Term2.Add(c1.ScalarMult(challenge))
	t2 = hs1.ScalarMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	// return False

	t1 = proof.Term3.Add(c.ServerPublicKey.ScalarMult(challenge))
	t2 = new(Point).ScalarBaseMult(proof.Res)

	gf.FreeInt(hs0.X, hs0.Y)
	gf.FreeInt(hs1.X, hs1.Y)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

func (c *Client) CreateVerifyPasswordRequest(nc, password []byte, t0 *Point) (c0 *Point) {
	hc0 := HashToPoint(nc, password, dhc0)
	minusY := gf.Neg(c.Y)
	c0 = t0.Add(hc0.ScalarMult(minusY))
	gf.FreeInt(hc0.X, hc0.Y)
	return
}

func (c *Client) CheckResponseAndDecrypt(t0, t1 *Point, password, ns, nc []byte, c1 *Point, proof *Proof, result bool) (m *Point, err error) {
	hc0 := HashToPoint(nc, password, dhc0)
	hc1 := HashToPoint(nc, password, dhc1)

	hs0 := HashToPoint(ns, dhs0)

	//c0 = t0 * (hc0 ** (-self.y))

	minusY := gf.Neg(c.Y)

	c0 := t0.Add(hc0.ScalarMult(minusY))

	if result && c.ValidateProof(proof, ns, c0, c1) {
		//return ((t1 * (c1 ** (-1))) *    (hc1 ** (-self.y))) ** (self.y ** (-1))

		m = (t1.Add(c1.Neg()).Add(hc1.ScalarMult(minusY))).ScalarMult(gf.Inv(c.Y))

		gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)

		return

	} else {
		challenge := HashZ(c.ServerPublicKey.Marshal(), curveG.Marshal(), c0.Marshal(), c1.Marshal(), proof.Term1.Marshal(), proof.Term2.Marshal(), proof.Term3.Marshal(), proof.Term4.Marshal(), proofError)
		//if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
		//return False
		//
		//if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
		//return False

		t1 := proof.Term1.Add(proof.Term2).Add(c1.ScalarMult(challenge))
		t2 := c0.ScalarMult(proof.Res1).Add(hs0.ScalarMult(proof.Res2))

		if !t1.Equal(t2) {
			gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)
			return nil, errors.New("proof verification failed")
		}

		t1 = proof.Term3.Add(proof.Term4).Add(proof.I.ScalarMult(challenge))
		t2 = c.ServerPublicKey.ScalarMult(proof.Res1).Add(new(Point).ScalarBaseMult(proof.Res2))

		if !t1.Equal(t2) {
			gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)
			return nil, errors.New("verification failed")
		}

	}

	gf.FreeInt(hs0.X, hs0.Y, hc0.X, hc0.Y, hc1.X, hc1.Y)

	return nil, nil
}

func (c *Client) Rotate(a *big.Int, newPub *Point) {
	c.Y = gf.Mul(c.Y, a)
	c.ServerPublicKey = newPub
}

func (c *Client) Update(t0, t1 *Point, ns []byte, a, b *big.Int) (t00, t11 *Point) {
	hs0 := HashToPoint(ns, dhs0)
	hs1 := HashToPoint(ns, dhs1)

	t00 = t0.ScalarMult(a).Add(hs0.ScalarMult(b))
	t11 = t1.ScalarMult(a).Add(hs1.ScalarMult(b))
	return
}
