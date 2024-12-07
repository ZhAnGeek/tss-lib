// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12377

import (
	"crypto/elliptic"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

type G2Curves struct {
	*elliptic.CurveParams
	Hg2 *big.Int // cofactor of elliptic group G2
}

func (curve *G2Curves) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// IsOnCurve returns bool to say if the point (x,y) is on elliptic group G2
// x,y should be 96 bytes
func (curve *G2Curves) IsOnCurve(x *big.Int, y *big.Int) bool {
	_, err := FromIntToPointG2(x, y)
	return err == nil
}

// Add return a point addition on elliptic group G2
func (curve *G2Curves) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1, err := FromIntToPointG2(x1, y1)
	if err != nil {
		panic("bls12377g2: invalid coordinates input")
	}
	p2, err := FromIntToPointG2(x2, y2)
	if err != nil {
		panic("bls12377g2: invalid coordinates input")
	}
	p3 := p1.Add(p1, p2)
	x, y = FromPointG2ToInt(p3)
	return
}

// Double return a point doubling on elliptic group G2
func (curve *G2Curves) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p1, err := FromIntToPointG2(x1, y1)
	if err != nil {
		panic("bls12377g2: invalid coordinates input")
	}
	p2 := p1.Double(p1)
	x, y = FromPointG2ToInt(p2)
	return
}

// ScalarMult returns k*(x1,y1) on elliptic group G2 over BLS12_377
func (curve *G2Curves) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	p, err := FromIntToPointG2(x1, y1)
	if err != nil {
		panic("bls12377g2: invalid coordinates input")
	}
	r := p.ScalarMultiplication(p, s)
	x, y = FromPointG2ToInt(r)
	return x, y
}

// ScalarBaseMult returns k*basePoint on elliptic group G2 over BLS12_377
func (curve *G2Curves) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	_, _, _, g2 := bls.Generators()
	// there is no ScalarMultiplicationBase
	r := g2.ScalarMultiplication(&g2, s)
	x, y = FromPointG2ToInt(r)
	return x, y
}

// initializes an instance of G2Curve curve
func (curve *G2Curves) init() {
	// Curve parameters taken from https://github.com/o1-labs/zexe/blob/master/algebra/src/bls12_377/curves/g2.rs
	curve.CurveParams = new(elliptic.CurveParams)

	curve.P = fp.Modulus()
	curve.N = fr.Modulus()
	// TODO: fix, Curve.B for G2 should consist of two coordinates from F_p^2 so it should be
	// [0, 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906]
	curve.B, _ = new(big.Int).SetString("155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906", 10)

	_, _, _, g2 := bls.Generators()
	x, y := FromPointG2ToInt(&g2)
	curve.Gx = x
	curve.Gy = y
	curve.Hg2, _ = new(big.Int).SetString("7923214915284317143930293550643874566881017850177945424769256759165301436616933228209277966774092486467289478618404761412630691835764674559376407658497", 10)
	curve.BitSize = fp.Modulus().BitLen()
}

// G2Curve returns a Curve which implements bls12381.
func G2Curve() *G2Curves {
	c := new(G2Curves)
	c.init()
	return c
}
