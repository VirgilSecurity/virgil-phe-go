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

func (p *Point) Neg() {
	p.Y = new(big.Int).Sub(Pn, p.Y)
}
