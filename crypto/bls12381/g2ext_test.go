// Copyright © 2019-2021 Binance
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

func TestG2Convert(t *testing.T) {
	g2 := bls.NewG2()
	point := bls.PointG2{}
	g2.MulScalar(&point, g2.One(), big.NewInt(666777))
	x, y := FromPointG2ToInt(&point)

	var point2 *bls.PointG2
	point2, err := FromIntToPointG2(x, y)
	assert.NoError(t, err)
	g2.Affine(point2)
	x2, y2 := FromPointG2ToInt(point2)

	assert.Equal(t, x.Cmp(x2), 0)
	assert.Equal(t, y.Cmp(y2), 0)
}
