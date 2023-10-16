// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

func BigIntsToBytes(bigInts []*big.Int) [][]byte {
	bzs := make([][]byte, len(bigInts))
	for i := range bzs {
		if bigInts[i] == nil {
			continue
		}
		bzs[i] = bigInts[i].Bytes()
	}
	return bzs
}

func MultiBytesToBigInts(bytes [][]byte) []*big.Int {
	ints := make([]*big.Int, len(bytes))
	for i := range ints {
		ints[i] = new(big.Int).SetBytes(bytes[i])
	}
	return ints
}

// NonEmptyBytes Returns true when the byte slice is non-nil and non-empty
func NonEmptyBytes(bz []byte) bool {
	return bz != nil && 0 < len(bz)
}

// NonEmptyMultiBytes Returns true when all of the slices in the multi-dimensional byte slice are non-nil and non-empty
func NonEmptyMultiBytes(bzs [][]byte, expectLen ...int) bool {
	if len(bzs) == 0 {
		return false
	}
	// variadic (optional) arg test
	if 0 < len(expectLen) && expectLen[0] != len(bzs) {
		return false
	}
	for _, bz := range bzs {
		if !NonEmptyBytes(bz) {
			return false
		}
	}
	return true
}

// PadToLengthBytesInPlace pad {0, ...} to the front of src if len(src) < length
// output length is equal to the parameter length
func PadToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}

func ReverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// BatchInvert inverts all elements of a
func BatchInvert(a []*big.Int, N *big.Int) ([]*big.Int, bool) {
	n := len(a)
	if n == 0 {
		return a, false
	}
	ret := make([]*big.Int, n)
	hasZero := false
	modQ := ModInt(N)

	accumulator := big.NewInt(1)
	zeroes := make([]bool, n)

	for i := 0; i < n; i++ {
		if a[i] == nil || a[i].Sign() == 0 {
			zeroes[i] = true
			hasZero = true
			continue
		}
		ret[i] = accumulator
		accumulator = modQ.Mul(accumulator, a[i])
	}

	invertAcc := modQ.ModInverse(accumulator)

	for i := len(a) - 1; i >= 0; i-- {
		if zeroes[i] {
			continue
		}
		ret[i] = modQ.Mul(ret[i], invertAcc)
		invertAcc = modQ.Mul(invertAcc, a[i])
	}

	return ret, hasZero
}
