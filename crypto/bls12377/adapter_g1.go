package bls12377

import (
	"crypto/elliptic"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
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
	_, err := FromIntToPointG1(x, y)
	return err == nil
}

// Add return a point addition on elliptic group G1
func (curve *G1Curves) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1, err := FromIntToPointG1(x1, y1)
	if err != nil {
		panic("bls12377g1: invalid coordinates input")
	}
	p2, err := FromIntToPointG1(x2, y2)
	if err != nil {
		panic("bls12377g1: invalid coordinates input")
	}
	p3 := p1.Add(p1, p2)
	x, y = FromPointG1ToInt(p3)
	return
}

// Double return a point doubling on elliptic group G1
func (curve *G1Curves) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p1, err := FromIntToPointG1(x1, y1)
	if err != nil {
		panic("bls12377g1: invalid coordinates input")
	}
	p2 := p1.Double(p1)
	x, y = FromPointG1ToInt(p2)
	return
}

// ScalarMult returns k*(x1,y1) on elliptic group G1 over BLS12_377
func (curve *G1Curves) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	p, err := FromIntToPointG1(x1, y1)
	if err != nil {
		panic("bls12377g1: invalid coordinates input")
	}
	r := p.ScalarMultiplication(p, s)
	x, y = FromPointG1ToInt(r)
	return x, y
}

// ScalarBaseMult returns k*basePoint on elliptic group G1 over BLS12_377
func (curve *G1Curves) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	var g1 bls.G1Affine
	r := g1.ScalarMultiplicationBase(s)
	x, y = FromPointG1ToInt(r)
	return x, y
}

// initializes an instance of G1Curve curve
func (curve *G1Curves) init() {
	// Curve parameters taken from https://github.com/o1-labs/zexe/blob/master/algebra/src/bls12_377/curves/g1.rs
	curve.CurveParams = new(elliptic.CurveParams)

	curve.P = fp.Modulus()
	curve.N = fr.Modulus()
	curve.B = new(big.Int).SetUint64(1)

	_, _, g1, _ := bls.Generators()
	x, y := FromPointG1ToInt(&g1)
	curve.Gx = x
	curve.Gy = y

	curve.Hg1, _ = new(big.Int).SetString("0x170B5D44300000000000000000000000", 16)
	curve.BitSize = fp.Modulus().BitLen()
}

// G1Curve returns a Curve which implements bls12381.
func G1Curve() *G1Curves {
	c := new(G1Curves)
	c.init()
	return c
}
