package bls12381

import (
	"crypto/elliptic"
	"math/big"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

type G1Curves struct {
	*elliptic.CurveParams
	Hg1 *big.Int // cofactor of elliptic group G1
}

func (curve *G1Curves) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// IsOnCurve returns bool to say if the point (x,y) is on elliptic group G1
// x,y should be 96 bytes
func (curve *G1Curves) IsOnCurve(x *big.Int, y *big.Int) bool {
	g1 := bls.NewG1()
	p, err := FromIntToPointG1(x, y)
	if err != nil {
		panic("bls12381g1: invalid coordinates input")
	}
	return g1.IsOnCurve(p)
}

// Add return a point addition on elliptic group G1
func (curve *G1Curves) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	g1 := bls.NewG1()
	p1, err := FromIntToPointG1(x1, y1)
	if err != nil {
		panic("bls12381g1: invalid coordinates input")
	}
	p2, err := FromIntToPointG1(x2, y2)
	if err != nil {
		panic("bls12381g1: invalid coordinates input")
	}
	r := g1.New()
	g1.Add(r, p1, p2)

	x, y = FromPointG1ToInt(r)
	return
}

// Double return a point doubling on elliptic group G1
func (curve *G1Curves) Double(x1, y1 *big.Int) (x, y *big.Int) {
	g1 := bls.NewG1()
	p1, err := FromIntToPointG1(x1, y1)
	if err != nil {
		panic("bls12381g1: invalid coordinates input")
	}
	r := g1.New()
	g1.Double(r, p1)
	x, y = FromPointG1ToInt(r)
	return
}

// ScalarMult returns k*(x1,y1) on elliptic group G1 over BLS12_381
func (curve *G1Curves) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	g1 := bls.NewG1()
	p, err := FromIntToPointG1(x1, y1)
	if err != nil {
		panic("bls12381g1: invalid coordinates input")
	}
	r := g1.New()
	G1MulScalarMont(r, p, s)
	x, y = FromPointG1ToInt(r)
	return x, y
}

// ScalarBaseMult returns k*basePoint on elliptic group G1 over BLS12_381
func (curve *G1Curves) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	g1 := bls.NewG1()
	r := g1.One()
	G1MulScalarMont(r, r, s)
	x, y = FromPointG1ToInt(r)
	return x, y
}

// initializes an instance of G1Curve curve
func (curve *G1Curves) init() {
	// Curve parameters taken from section[4.2.1] https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-07#section-2.1
	curve.CurveParams = new(elliptic.CurveParams)

	curve.P = modulus.big()
	curve.N = bls.NewG1().Q()
	curve.B = big.NewInt(4)

	g1 := bls.NewG1()
	bP := g1.One()
	x, y := FromPointG1ToInt(bP)
	curve.Gx = x
	curve.Gy = y

	curve.Hg1 = cofactorEFFG1
	curve.BitSize = 256
}

// G1Curve returns a Curve which implements bls12381.
func G1Curve() *G1Curves {
	c := new(G1Curves)
	c.init()
	return c
}
