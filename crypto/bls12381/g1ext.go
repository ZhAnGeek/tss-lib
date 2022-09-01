package bls12381

import (
	"math/big"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

func FromIntToPointG1(x, y *big.Int) (*bls.PointG1, error) {
	p := bls.NewG1()
	in := make([]byte, 48*2)
	copy(x.Bytes(), in[:48])
	copy(y.Bytes(), in[48:96])
	g1, err := p.FromBytes(in)
	if err != nil {
		return nil, err
	}
	return g1, nil
}

func FromPointG1ToInt(g1 *bls.PointG1) (*big.Int, *big.Int) {
	p := bls.NewG1()
	out := p.ToBytes(g1)
	x := new(big.Int).SetBytes(out[:48])
	y := new(big.Int).SetBytes(out[48:])
	return x, y
}
