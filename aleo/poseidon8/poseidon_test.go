// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package poseidon8

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	v1, ok := new(big.Int).SetString("2747380058067926024392396834194632562725011784276175733372764264674145639690", 10)
	assert.True(t, ok)
	v2, ok := new(big.Int).SetString("4669766862083161671500363968195935072348039486297434174954457851807822454654", 10)
	assert.True(t, ok)
	fmt.Println("v:", v1, v2)

	h := HashPSD8([]*big.Int{v1, v2})
	fmt.Println("hash:", h)
	expected, ok := new(big.Int).SetString("1180359748656709782892394045578889757465705762300940994128806594490438587347", 10)
	assert.True(t, ok)
	assert.Zero(t, h.Cmp(expected))
}
