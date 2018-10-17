package swu

/*
 Implementation of Shallue-Woestijne-Ulas algorithm in Go
*/

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
)

var (
	p        = elliptic.P256().Params().P
	a        *big.Int
	b        = elliptic.P256().Params().B
	mba      *big.Int
	gf       = &GF{p}
	p34, p14 *big.Int
)

func init() {
	a = gf.Neg(three)
	ba := gf.Div(b, a)
	mba = gf.Neg(ba)
	p3 := gf.Sub(p, three)
	p34 = gf.Div(p3, four)
	p1 := gf.Add(p, one)
	p14 = gf.Div(p1, four)
}

//DataToPoint hashes data using SHA-256 and maps it to a point on curve
func DataToPoint(data []byte) (x, y *big.Int) {
	hash := sha256.Sum256(data)
	return HashToPoint(hash[:])
}

//HashToPoint maps 32 byte hash to a point on curve
func HashToPoint(hash []byte) (x, y *big.Int) {

	if len(hash) != 32 {
		panic("invalid hash length")
	}

	t := new(big.Int).SetBytes(hash)
	t.Mod(t, p)

	//alpha = -t^2
	tt := gf.Square(t)

	alpha := gf.Neg(tt)

	asq := gf.Square(alpha)
	asqa := gf.Add(asq, alpha)
	asqa1 := gf.Add(one, gf.Inv(asqa))

	// x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
	x2 := gf.Mul(mba, asqa1)

	//x3 = alpha * x2
	x3 := gf.Mul(alpha, x2)

	ax2 := gf.Mul(a, x2)
	x23 := gf.Cube(x2)
	x23ax2 := gf.Add(x23, ax2)

	// h2 = x2^3 + a*x2 + b
	h2 := gf.Add(x23ax2, b)

	ax3 := gf.Mul(a, x3)
	x33 := gf.Cube(x3)
	x33ax3 := gf.Add(x33, ax3)

	// h3 = x3^3 + a*x3 + b
	h3 := gf.Add(x33ax3, b)

	// tmp = h2 ^ ((p - 3) // 4)
	tmp := gf.Pow(h2, p34)

	tmp2 := gf.Square(tmp)
	tmp2h2 := gf.Mul(tmp2, h2)

	//if tmp^2 * h2 == 1:
	if tmp2h2.Cmp(one) == 0 {
		// return (x2, tmp * h2 )
		return x2, gf.Mul(tmp, h2)
	}

	//return (x3, h3 ^ ((p+1)//4))
	return x3, gf.Pow(h3, p14)
}
