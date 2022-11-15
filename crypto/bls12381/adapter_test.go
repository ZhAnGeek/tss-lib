// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12381

import (
	"math/big"
	"testing"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/stretchr/testify/assert"
)

func TestAdapter(t *testing.T) {
	p := BLS12381()

	g2 := bls.NewG2()
	sk := big.NewInt(20).Bytes()
	pk := G2MulScalarMont(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))
	x, y := FromPointG2ToInt(pk)
	assert.Equal(t, true, p.IsOnCurve(x, y))

	xx, yy := p.ScalarBaseMult(sk)
	assert.Equal(t, x, xx)
	assert.Equal(t, y, yy)
}

func TestScalaMulG1(t *testing.T) {
	g1 := bls.NewG1()
	point := bls.PointG1{}
	G1MulScalarMont(&point, g1.One(), big.NewInt(666777))
	x, y := FromPointG1ToInt(&point)

	point2 := bls.PointG1{}
	G1MulScalarMont(&point2, g1.One(), big.NewInt(666777))
	x2, y2 := FromPointG1ToInt(&point2)
	assert.Equal(t, x.Cmp(x2), 0)
	assert.Equal(t, y.Cmp(y2), 0)
}

func TestScalaMulG2(t *testing.T) {
	g2 := bls.NewG2()
	point := bls.PointG2{}
	G2MulScalarMont(&point, g2.One(), big.NewInt(666777))
	x, y := FromPointG2ToInt(&point)

	point2 := bls.PointG2{}
	G2MulScalarMont(&point2, g2.One(), big.NewInt(666777))
	x2, y2 := FromPointG2ToInt(&point2)
	assert.Equal(t, x.Cmp(x2), 0)
	assert.Equal(t, y.Cmp(y2), 0)
}
