package bls12381

import (
	"math/big"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

func FromIntToPointG2(x, y *big.Int) (*bls.PointG2, error) {
	p := bls.NewG2()
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
	g2, err := p.FromBytes(in)
	if err != nil {
		return nil, err
	}
	return g2, nil
}

// this function translate a G2 projective point into two big integers
func FromPointG2ToInt(g2 *bls.PointG2) (*big.Int, *big.Int) {
	p := bls.NewG2()
	out := p.ToBytes(g2) //out is in affine coordinates
	x := new(big.Int).SetBytes(out[:96])
	y := new(big.Int).SetBytes(out[96:])
	return x, y
}
