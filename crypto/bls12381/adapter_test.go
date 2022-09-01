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
	pk := g2.MulScalar(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))
	x, y := FromPointG2ToInt(pk)
	assert.Equal(t, true, p.IsOnCurve(x, y))

	xx, yy := p.ScalarBaseMult(sk)
	assert.Equal(t, x, xx)
	assert.Equal(t, y, yy)

	g1 := bls.NewG1()
	pkPrime := g1.MulScalar(&bls.PointG1{}, g1.One(), new(big.Int).SetBytes(sk))
	xPrime, yPrime := FromPointG1ToInt(pkPrime)
	assert.Equal(t, true, p.IsOnG1(xPrime, yPrime))

	xxPrime, yyPrime := p.ScalarBaseMultOnG1(sk)
	assert.Equal(t, xPrime, xxPrime)
	assert.Equal(t, yPrime, yyPrime)

}
