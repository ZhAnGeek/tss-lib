// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12377

import (
	"errors"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

func FromIntToPointG1(x, y *big.Int) (*bls.G1Affine, error) {
	in := make([]byte, 96)
	xx := x.Bytes()
	yy := y.Bytes()
	xx, err := PadToLengthBytesInPlace(xx, 48)
	if err != nil {
		return nil, err
	}
	yy, err = PadToLengthBytesInPlace(yy, 48)
	if err != nil {
		return nil, err
	}
	copy(in[:48], xx)
	copy(in[48:], yy)
	var p bls.G1Affine
	err = p.Unmarshal(in)
	if err != nil {
		return nil, errors.New("invalid coordinates for BLS12-377 G2")
	}
	return &p, nil
}

// this function translate a G2 projective point into two big integers
func FromPointG1ToInt(g1 *bls.G1Affine) (*big.Int, *big.Int) {
	out := g1.Marshal() // out is in affine coordinates
	x := new(big.Int).SetBytes(out[:48])
	y := new(big.Int).SetBytes(out[48:])
	return x, y
}
