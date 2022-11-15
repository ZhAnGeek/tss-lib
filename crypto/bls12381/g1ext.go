// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12381

import (
	"math/big"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

func FromIntToPointG1(x, y *big.Int) (*bls.PointG1, error) {
	p := bls.NewG1()
	in := make([]byte, 96)
	xx := x.Bytes()
	yy := y.Bytes()
	xx = PadToLengthBytesInPlace(xx, 48)
	yy = PadToLengthBytesInPlace(yy, 48)
	copy(in[:48], xx)
	copy(in[48:], yy)
	g1, err := p.FromBytes(in)
	if err != nil {
		return nil, err
	}
	return g1, nil
}

// this function translate a G2 projective point into two big integers
func FromPointG1ToInt(g1 *bls.PointG1) (*big.Int, *big.Int) {
	p := bls.NewG1()
	out := p.ToBytes(g1) // out is in affine coordinates
	x := new(big.Int).SetBytes(out[:48])
	y := new(big.Int).SetBytes(out[48:])
	return x, y
}
