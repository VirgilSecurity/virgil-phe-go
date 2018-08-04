package phe

import (
	"crypto/rand"
	"testing"

	"github.com/Scratch-net/SWU"
	"github.com/ameteiko/golang-kit/test/assert"
)

func TestPoint_Add_Neg(t *testing.T) {

	p1 := MakePoint()
	p2 := MakePoint()
	p3 := MakePoint()

	p12 := p1.Add(p2)
	p123 := p12.Add(p3)

	p1 = p1.Neg()
	p2 = p2.Neg()

	p123 = p123.Add(p1)
	p123 = p123.Add(p2)

	assert.Equal(t, p3, p123)
}

func MakePoint() *Point {
	b := make([]byte, 32)
	rand.Read(b)
	x, y := swu.HashToPoint(b)
	return &Point{x, y}
}
