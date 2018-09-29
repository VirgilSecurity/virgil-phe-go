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
	F        = &GF{p}
	p34, p14 *big.Int
)

func init() {
	a = F.Neg(Three)
	ba := F.Div(b, a)
	mba = F.Neg(ba)
	p3 := F.Sub(p, Three)
	p34 = F.Div(p3, Four)
	p1 := F.Add(p, One)
	p14 = F.Div(p1, Four)
}

func HashToPoint(data []byte) (x, y *big.Int) {

	hash := sha256.Sum256(data)

	t := new(big.Int).SetBytes(hash[:])
	t.Mod(t, p)

	//alpha = -t^2
	tt := F.Square(t)

	alpha := F.Neg(tt)

	asq := F.Square(alpha)
	asqa := F.Add(asq, alpha)
	asqa1 := F.Add(One, F.Inv(asqa))

	// x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
	x2 := F.Mul(mba, asqa1)

	//x3 = alpha * x2
	x3 := F.Mul(alpha, x2)

	ax2 := F.Mul(a, x2)
	x23 := F.Cube(x2)
	x23ax2 := F.Add(x23, ax2)

	// h2 = x2^3 + a*x2 + b
	h2 := F.Add(x23ax2, b)

	ax3 := F.Mul(a, x3)
	x33 := F.Cube(x3)
	x33ax3 := F.Add(x33, ax3)

	// h3 = x3^3 + a*x3 + b
	h3 := F.Add(x33ax3, b)

	// tmp = h2 ^ ((p - 3) // 4)
	tmp := F.Pow(h2, p34)

	tmp2 := F.Square(tmp)
	tmp2h2 := F.Mul(tmp2, h2)

	//if tmp^2 * h2 == 1:
	if tmp2h2.Cmp(One) == 0 {
		// return (x2, tmp * h2 )
		return x2, F.Mul(tmp, h2)
	} else {
		//return (x3, h3 ^ ((p+1)//4))
		return x3, F.Pow(h3, p14)
	}
}
