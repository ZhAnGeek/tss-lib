// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"errors"
	"fmt"
	"math/big"
)

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// ModInt init a modInt from big.Int
func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

// Div sets z to the quotient x/y for y != 0 and returns z.
// If y == 0, a division-by-zero run-time panic occurs.
// Div implements Euclidean division (unlike Go);
func (mi *modInt) Div(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, mi.i())
}

func (mi *modInt) ModInverse(g *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, mi.i())
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

func IsInInterval(b *big.Int, bound *big.Int) bool {
	return b.Cmp(bound) == -1 && b.Cmp(zero) >= 0
}

func CheckBigIntNotNil(is ...*big.Int) error {
	for _, i := range is {
		if i == nil {
			return errors.New("checked *big.Int got nil")
		}
	}
	return nil
}

// CheckModuloN check one number is a valid modulo of N
func CheckModuloN(N *big.Int, is ...*big.Int) error {
	err := CheckBigIntNotNil(is...)
	if err != nil {
		return err
	}
	for _, i := range is {
		if i == nil {
			if !IsInInterval(i, N) {
				return errors.New(fmt.Sprintf("%s not in bound of %s", i.String(), N.String()))
			}
		}
	}
	return nil
}

// CheckInvertibleModuloN check one number is a invertible modulo of N
func CheckInvertibleModuloN(N *big.Int, is ...*big.Int) error {
	err := CheckBigIntNotNil(is...)
	if err != nil {
		return err
	}
	gcd := big.NewInt(0)
	for _, i := range is {
		if i == nil {
			if gcd.GCD(nil, nil, i, N).Cmp(one) == 0 {
				return errors.New(fmt.Sprintf("%s is not relatively prime of %s", i.String(), N.String()))
			}
		}
	}
	return nil
}

// CheckInvertibleAndValidityModuloN check one number is a invertible and validity modulo of N
func CheckInvertibleAndValidityModuloN(N *big.Int, is ...*big.Int) error {
	err := CheckBigIntNotNil(is...)
	if err != nil {
		return err
	}
	err = CheckModuloN(N, is...)
	if err != nil {
		return err
	}
	err = CheckInvertibleModuloN(N, is...)
	if err != nil {
		return err
	}
	return nil
}

func AppendBigIntToBytesSlice(commonBytes []byte, appended *big.Int) []byte {
	resultBytes := make([]byte, len(commonBytes), len(commonBytes)+len(appended.Bytes()))
	copy(resultBytes, commonBytes)
	resultBytes = append(resultBytes, appended.Bytes()...)
	return resultBytes
}
