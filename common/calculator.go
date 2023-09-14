// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

var _intCalc IntCalculator = NewBigIntCalculator()

func IntCalc() IntCalculator {
	return _intCalc
}

func SetIntCalc(newCalc IntCalculator) {
	_intCalc = newCalc
}

// IntCalculator is an interface for big.Int math operations
type IntCalculator interface {
	Name() string
	Exp(x, y, m *big.Int) *big.Int
}

type BigIntCalculator struct{}

func NewBigIntCalculator() *BigIntCalculator {
	return &BigIntCalculator{}
}

func (b *BigIntCalculator) Name() string {
	return "golang.big.Int"
}

func (b *BigIntCalculator) Exp(x, y, m *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, m)
}
