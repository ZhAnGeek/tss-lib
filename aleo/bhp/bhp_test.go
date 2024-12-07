// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bhp

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBHP1(t *testing.T) {
	v := []bool{true, true, false, true}
	expected, ok := new(big.Int).SetString("4465270488049114119548221835358046659094034035495956862619245177230472468585", 10)
	assert.True(t, ok)
	res := HashBHP1024(v)
	assert.Zero(t, expected.Cmp(res))
}

func TestBHP2(t *testing.T) {
	v := make([]bool, 1536)
	for i := range v {
		v[i] = false
	}
	v[0] = true
	v[1] = true
	v[3] = true
	v[1200] = true
	expected, ok := new(big.Int).SetString("5585470739558495335706531269370447027840989798419035381790505936848217177091", 10)
	assert.True(t, ok)
	res := HashBHP1024(v)
	assert.Zero(t, expected.Cmp(res))
}

func TestFoo(t *testing.T) {
	str := "abc"
	bzs := []byte(str)
	bits := BytesToBits(bzs)
	fmt.Println(bzs, bits)
}
