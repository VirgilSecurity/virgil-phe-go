package phe

import (
	"crypto/elliptic"
	"math/big"

	"github.com/pkg/errors"
)

type Point struct {
	X, Y *big.Int
}

var (
	Pn = curve.Params().P
)

func PointUnmarshal(data []byte) (*Point, error) {
	if len(data) > 65 {
		return nil, errors.New("Invalid curve point")
	}
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil || y == nil {
		return nil, errors.New("Invalid curve point")
	}
	return &Point{
		X: x,
		Y: y,
	}, nil
}

func (p *Point) Add(a *Point) *Point {
	x, y := curve.Add(p.X, p.Y, a.X, a.Y)
	return &Point{x, y}
}

func (p *Point) Neg() *Point {
	t := new(Point)
	t.X = p.X
	t.Y = new(big.Int).Sub(Pn, p.Y)
	return t
}

func (p *Point) ScalarMult(b *big.Int) *Point {
	x, y := curve.ScalarMult(p.X, p.Y, b.Bytes())

	return &Point{x, y}
}

func (p *Point) ScalarBaseMult(b *big.Int) *Point {
	x, y := curve.ScalarBaseMult(b.Bytes())

	return &Point{x, y}
}

func (p *Point) Marshal() []byte {
	return elliptic.Marshal(curve, p.X, p.Y)
}

func (p *Point) Equal(other *Point) bool {
	return p.X.Cmp(other.X) == 0 &&
		p.Y.Cmp(other.Y) == 0
}
