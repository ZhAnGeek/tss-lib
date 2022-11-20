// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12381

import (
	"crypto/elliptic"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

// Efficient cofactor of G2Curve
var cofactorEFFG1 = bigFromHex("0xd201000000010001")

// Efficient cofactor of G2
var cofactorEFFG2 = bigFromHex("0x0bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551")

func bigFromHex(hex string) *big.Int {
	return new(big.Int).SetBytes(common.FromHex(hex))
}

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
	g2 := bls.NewG2()
	p, err := FromIntToPointG2(x, y)
	if err != nil {
		panic("bls12381g2: invalid coordinates input")
	}
	return g2.IsOnCurve(p)
}

// Add return a point addition on elliptic group G2
func (curve *G2Curves) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	g2 := bls.NewG2()
	p1, err := FromIntToPointG2(x1, y1)
	if err != nil {
		panic("bls12381g2: invalid coordinates input")
	}
	p2, err := FromIntToPointG2(x2, y2)
	if err != nil {
		panic("bls12381g2: invalid coordinates input")
	}
	r := g2.New()
	g2.Add(r, p1, p2)

	x, y = FromPointG2ToInt(r)
	return
}

// Double return a point doubling on elliptic group G2
func (curve *G2Curves) Double(x1, y1 *big.Int) (x, y *big.Int) {
	g2 := bls.NewG2()
	p1, err := FromIntToPointG2(x1, y1)
	if err != nil {
		panic("bls12381g2: invalid coordinates input")
	}
	r := g2.New()
	g2.Double(r, p1)
	x, y = FromPointG2ToInt(r)
	return
}

// ScalarMult returns k*(x1,y1) on elliptic group G2 over BLS12_381
func (curve *G2Curves) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	g2 := bls.NewG2()
	p, err := FromIntToPointG2(x1, y1)
	if err != nil {
		panic("bls12381g2: invalid coordinates input")
	}
	r := g2.New()
	// g2.MulScalar(r, p, s) // r result r is represented in projective coordinates
	G2MulScalarMont(r, p, s)
	x, y = FromPointG2ToInt(r)
	return x, y
}

// ScalarBaseMult returns k*basePoint on elliptic group G2 over BLS12_381
func (curve *G2Curves) ScalarBaseMult(k []byte) (x, y *big.Int) {
	s := new(big.Int).SetBytes(k)
	g2 := bls.NewG2()
	r := g2.One()
	// g2.MulScalar(r, r, s)
	G2MulScalarMont(r, r, s)
	x, y = FromPointG2ToInt(r)
	return x, y
}

// initializes an instance of G2Curve curve
func (curve *G2Curves) init() {
	// Curve parameters taken from section[4.2.1] https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-07#section-2.1
	curve.CurveParams = new(elliptic.CurveParams)

	curve.P = modulus.big()
	curve.N = bls.NewG1().Q()
	curve.B = big.NewInt(4)

	g2 := bls.NewG2()
	bP := g2.One()
	x, y := FromPointG2ToInt(bP)
	curve.Gx = x
	curve.Gy = y

	curve.Hg2 = cofactorEFFG2
	curve.BitSize = 256
}

// G2Curve returns a Curve which implements bls12381.
func G2Curve() *G2Curves {
	c := new(G2Curves)
	c.init()
	return c
}
