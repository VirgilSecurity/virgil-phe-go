package phe

import (
	"crypto/elliptic"
	"math/big"
)

type Point struct {
	X, Y *big.Int
}

var (
	c  = elliptic.P256()
	Pn = c.Params().P
)

func (p *Point) Add(a *Point) *Point {
	x, y := c.Add(p.X, p.Y, a.X, a.Y)
	return &Point{x, y}
}

func (p *Point) Neg() *Point {
	t := new(Point)
	t.X = p.X
	t.Y = new(big.Int).Sub(Pn, p.Y)
	return t
}

func (p *Point) ScalarMult(b []byte) *Point {
	x, y := c.ScalarMult(p.X, p.Y, b)

	return &Point{x, y}
}

func (p *Point) ScalarBaseMult(b []byte) *Point {
	x, y := c.ScalarBaseMult(b)

	return &Point{x, y}
}

func (p *Point) Marshal() []byte {
	return elliptic.Marshal(c, p.X, p.Y)
}

func (p *Point) Equal(other *Point) bool {
	return p.X.Cmp(other.X) == 0 &&
		p.Y.Cmp(other.Y) == 0
}
