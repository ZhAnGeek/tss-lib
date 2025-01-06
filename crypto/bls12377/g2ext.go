package bls12377

import (
	"errors"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

func FromIntToPointG2(x, y *big.Int) (*bls.G2Affine, error) {
	in := make([]byte, 192)
	xx := x.Bytes()
	yy := y.Bytes()
	xx, err := PadToLengthBytesInPlace(xx, 96)
	if err != nil {
		return nil, err
	}
	yy, err = PadToLengthBytesInPlace(yy, 96)
	if err != nil {
		return nil, err
	}
	copy(in[:96], xx)
	copy(in[96:], yy)
	var p bls.G2Affine
	err = p.Unmarshal(in)
	if err != nil {
		return nil, errors.New("invalid coordinates for BLS12-377 G2")
	}
	return &p, nil
}

// this function translate a G2 projective point into two big integers
func FromPointG2ToInt(g2 *bls.G2Affine) (*big.Int, *big.Int) {
	out := g2.Marshal() // out is in affine coordinates
	x := new(big.Int).SetBytes(out[:96])
	y := new(big.Int).SetBytes(out[96:])
	return x, y
}
