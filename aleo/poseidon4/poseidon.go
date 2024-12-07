// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package poseidon4

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/hash2curve"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	// Rf * 2 full rounds
	Rf = 4
	// Rp partial rounds
	Rp = 31
	// Capacity states are placed before Rate states
	Capacity = 1
	Rate     = 4
)

var (
	alpha = big.NewInt(17)
	Arc   [][]*big.Int
	Mds   [][]*big.Int
	// domainSep from "AleoPoseidon4"
	domainSep, _ = new(big.Int).SetString("4154042466768937459977837440065", 10)
	Modulus, _   = new(big.Int).SetString("8444461749428370424248824938781546531375899335154063827935233455917409239041", 10)
	modN         = common.ModInt(Modulus)
	// scalar modulus 2747380058067926024392396834194632562725011784276175733372764264674145639690
	// scalarDataLen = nBits(scalar modulus) - 1
	scalarDataLen = 250
)

type state struct {
	// size of Capacity + Rate
	items []*big.Int
}

func (s *state) initialize() {
	s.items = make([]*big.Int, Rate+Capacity)
	for i := range s.items {
		s.items[i] = common.Zero
	}
}

func (s *state) applyARC(roundNumber int) {
	for i, val := range s.items {
		s.items[i] = modN.Add(val, Arc[roundNumber][i])
	}
}

func (s *state) applySBOX(isFullRound bool) {
	if isFullRound {
		for i, val := range s.items {
			s.items[i] = modN.Exp(val, alpha)
		}
	} else {
		s.items[0] = modN.Exp(s.items[0], alpha)
	}
}

func (s *state) applyMDS() {
	t := len(s.items)
	newItems := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		sum := new(big.Int)
		for j := 0; j < t; j++ {
			sum = modN.Add(sum, modN.Mul(s.items[j], Mds[i][j]))
		}
		newItems[i] = sum
	}
	s.items = newItems
}

func (s *state) permute() {
	for i := 0; i < Rf; i++ {
		s.applyARC(i)
		s.applySBOX(true)
		s.applyMDS()
	}
	for i := Rf; i < Rf+Rp; i++ {
		s.applyARC(i)
		s.applySBOX(false)
		s.applyMDS()
	}
	for i := Rf + Rp; i < Rf+Rp+Rf; i++ {
		s.applyARC(i)
		s.applySBOX(true)
		s.applyMDS()
	}
}

func HashToScalarPSD4(input []*big.Int) *big.Int {
	preImage := make([]*big.Int, Rate+len(input))
	preImage[0] = domainSep
	preImage[1] = big.NewInt(int64(len(input)))
	for i := 2; i < Rate; i++ {
		preImage[i] = common.Zero
	}
	for i := Rate; i < Rate+len(input); i++ {
		preImage[i] = input[i-Rate]
	}
	// padding
	if (len(preImage) % Rate) != 0 {
		pad := make([]*big.Int, Rate-(len(preImage)%Rate))
		for j := range pad {
			pad[j] = common.Zero
		}
		preImage = append(preImage, pad...)
	}

	// absorb
	var sta state
	sta.initialize()
	totalNumChunks := len(preImage) / Rate
	// absorb chunks
	offset := 0
	for j := 0; j < totalNumChunks; j++ {
		for i := 0; i < Rate; i++ {
			sta.items[Capacity+i] = modN.Add(sta.items[Capacity+i], preImage[offset+i])
		}
		offset += Rate
		sta.permute()
	}

	// squeeze out the Rate state
	output := sta.items[Capacity]

	// hash to scalar
	ret := output
	for i := scalarDataLen; i < output.BitLen(); i++ {
		ret = new(big.Int).SetBit(ret, i, 0)
	}
	return ret
}

func HashToPointsPSD4(input []*big.Int) (*big.Int, *big.Int) {
	preImage := make([]*big.Int, Rate+len(input))
	preImage[0] = domainSep
	preImage[1] = big.NewInt(int64(len(input)))
	for i := 2; i < Rate; i++ {
		preImage[i] = common.Zero
	}
	for i := Rate; i < Rate+len(input); i++ {
		preImage[i] = input[i-Rate]
	}
	// padding
	if (len(preImage) % Rate) != 0 {
		pad := make([]*big.Int, Rate-(len(preImage)%Rate))
		for j := range pad {
			pad[j] = common.Zero
		}
		preImage = append(preImage, pad...)
	}

	// absorb
	var sta state
	sta.initialize()
	totalNumChunks := len(preImage) / Rate
	// absorb chunks
	offset := 0
	for j := 0; j < totalNumChunks; j++ {
		for i := 0; i < Rate; i++ {
			sta.items[Capacity+i] = modN.Add(sta.items[Capacity+i], preImage[offset+i])
		}
		offset += Rate
		sta.permute()
	}

	// squeeze out the Rate state
	output := sta.items[Capacity : Capacity+2]

	return output[0], output[1]
}

func HashToGroup(inputs []*big.Int, id hash2curve.SuiteID) (*crypto.ECPoint, error) {
	x, y := HashToPointsPSD4(inputs)

	suite, err := hash2curve.GetSuiteByID(id)

	if err != nil {
		return nil, errors.New("not supported suite")
	}

	e := suite.E.Get()
	map2Curve := suite.Map.Get(e)
	p1 := map2Curve.Map(e.Field().Elt(x))
	p2 := map2Curve.Map(e.Field().Elt(y))

	r := e.Add(p1, p2)
	p := e.ClearCofactor(r)

	var curve elliptic.Curve
	switch id {
	case hash2curve.EdBLS12377_XMDSHA512_ELL2_RO_:
		curve = tss.EdBls12377()
	default:
		return nil, errors.New("not supported suite")
	}
	return crypto.NewECPoint(curve, p.X().Polynomial()[0], p.Y().Polynomial()[0])
}
