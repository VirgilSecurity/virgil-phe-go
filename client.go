package phe

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type Client struct {
	Y *big.Int
}

func (c *Client) EnrollAccount(password, ns []byte, c0 *Point, proof *Proof) (nc []byte, t0 *Point, err error) {
	nc = make([]byte, 32)
	rand.Read(nc)

	hc0 := HashToPoint(nc, password, dhc0)

	proofValid := c.ValidateProof(proof, ns, c0)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	t0 = c0.Add(hc0.ScalarMult(c.Y))
	return
}

func (c *Client) ValidateProof(proof *Proof, nonce []byte, c0 *Point) bool {

	hs0 := HashToPoint(nonce, dhs0)

	challenge := HashZ(proof.PublicKey.Marshal(), curveG.Marshal(), c0.Marshal(), proof.Term1.Marshal(), proof.Term3.Marshal(), proofOk)

	//if term1 * (c0 ** challenge) != hs0 ** blind_x:
	// return False

	t1 := proof.Term1.Add(c0.ScalarMult(challenge))
	t2 := hs0.ScalarMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	// return False

	t1 = proof.Term3.Add(proof.PublicKey.ScalarMult(challenge))
	t2 = new(Point).ScalarBaseMult(proof.Res)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

func (c *Client) CreateVerifyPasswordRequest(nc, password []byte, t0 *Point) (c0 *Point) {
	hc0 := HashToPoint(nc, password, dhc0)
	minusY := gf.Neg(c.Y)
	c0 = t0.Add(hc0.ScalarMult(minusY))
	return
}

func (c *Client) CheckResponseAndDecrypt(t0 *Point, password, ns, nc []byte, proof *Proof, result bool) (err error) {
	hc0 := HashToPoint(nc, password, dhc0)

	hs0 := HashToPoint(ns, dhs0)

	//c0 = t0 * (hc0 ** (-self.y))

	minusY := gf.Neg(c.Y)

	c0 := t0.Add(hc0.ScalarMult(minusY))

	if result && c.ValidateProof(proof, ns, c0) {
		return nil

	} else {
		challenge := HashZ(proof.PublicKey.Marshal(), curveG.Marshal(), c0.Marshal(), proof.C1.Marshal(), proof.Term1.Marshal(), proof.Term2.Marshal(), proof.Term3.Marshal(), proof.Term4.Marshal(), proofError)
		fmt.Println(challenge)
		//if term1 * term2 * (C1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
		//return False
		//
		//if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
		//return False

		t1 := proof.Term1.Add(proof.Term2).Add(proof.C1.ScalarMult(challenge))
		t2 := c0.ScalarMult(proof.Res1).Add(hs0.ScalarMult(proof.Res2))

		if !t1.Equal(t2) {
			return errors.New("proof verification failed")
		}

		t1 = proof.Term3.Add(proof.Term4).Add(proof.I.ScalarMult(challenge))
		t2 = proof.PublicKey.ScalarMult(proof.Res1).Add(new(Point).ScalarBaseMult(proof.Res2))

		if !t1.Equal(t2) {
			return errors.New("verification failed")
		}

	}

	return nil
}

func (c *Client) Rotate(a *big.Int) {
	c.Y = gf.Mul(c.Y, a)
}

func (c *Client) Update(t0, t1 *Point, ns []byte, a, b *big.Int) (t00, t11 *Point) {
	hs0 := HashToPoint(ns, dhs0)
	hs1 := HashToPoint(ns, dhs1)

	t00 = t0.ScalarMult(a).Add(hs0.ScalarMult(b))
	t11 = t1.ScalarMult(a).Add(hs1.ScalarMult(b))
	return
}
