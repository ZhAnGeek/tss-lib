// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12377

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEdBLS12377BasePoint(t *testing.T) {

	bls12377 := EdBls12377Curve()
	x, y := bls12377.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())

	assert.Equal(t, bls12377.Params().Gx.String(), x.String())
	assert.Equal(t, bls12377.Params().Gy.String(), y.String())
}

func TestEdBLS12377DoubleAndAdd(t *testing.T) {

	bls12377 := EdBls12377Curve()
	x2, y2 := bls12377.ScalarBaseMult(new(big.Int).SetInt64(2).Bytes())

	assert.Equal(t, "635729210006270224914087040697919839390416031021817704229162077382650990011", x2.String())
	assert.Equal(t, "2715027396194992440884724922975940687547603080066254501565260354846395663765", y2.String())

	x2d, y2d := bls12377.Double(bls12377.Gx, bls12377.Gy)
	assert.Equal(t, "635729210006270224914087040697919839390416031021817704229162077382650990011", x2d.String())
	assert.Equal(t, "2715027396194992440884724922975940687547603080066254501565260354846395663765", y2d.String())
}

func TestEdBLS12377IsOnCurve(t *testing.T) {
	bls12377 := EdBls12377Curve()
	x, y := bls12377.ScalarBaseMult(new(big.Int).SetInt64(100).Bytes())
	y.Add(y, big.NewInt(1))
	assert.False(t, bls12377.IsOnCurve(x, y))

}
