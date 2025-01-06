// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bhp

import (
	_ "embed"
	"encoding/json"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/crypto"
)

type DumpedBases struct {
	X [][]*big.Int
	Y [][]*big.Int
}

type DumpedRandomBase struct {
	X []*big.Int
	Y []*big.Int
}

var (
	// params dumped from https://github.com/AleoNet/snarkVM/blob/4965f6b64eaf283ccdf192abde6a58554245b89f/console/network/src/mainnet_v0.rs#L57
	//go:embed bases.data
	basesBytes []byte
	//go:embed random_base.data
	randomBasesBytes []byte
)

func init() {
	var bases DumpedBases
	{
		err := json.Unmarshal(basesBytes, &bases)
		if err != nil {
			panic(err)
		}
	}

	var randomBase DumpedRandomBase
	{
		err := json.Unmarshal(randomBasesBytes, &randomBase)
		if err != nil {
			panic(err)
		}
	}

	Bases = make([][]*crypto.ECPoint, len(bases.X))
	for i, row := range bases.X {
		Bases[i] = make([]*crypto.ECPoint, len(row))
		for j := range row {
			point, err := crypto.NewECPoint(ec, bases.X[i][j], bases.Y[i][j])
			if err != nil {
				panic(err)
			}
			Bases[i][j] = point
		}
	}
	RandomBase = make([]*crypto.ECPoint, len(randomBase.X))
	for i := range randomBase.X {
		point, err := crypto.NewECPoint(ec, randomBase.X[i], randomBase.Y[i])
		if err != nil {
			panic(err)
		}
		RandomBase[i] = point
	}
	BasesLookup = make([][][]*crypto.ECPoint, len(Bases))
	for i, row := range Bases {
		BasesLookup[i] = make([][]*crypto.ECPoint, len(row))
		for j, g := range row {
			BasesLookup[i][j] = make([]*crypto.ECPoint, LookupSize)
			for k := 0; k < LookupSize; k++ {
				element := g
				var err error
				if k&0x1 != 0 {
					element, err = element.Add(g)
					if err != nil {
						panic(err)
					}
				}
				if k&0x2 != 0 {
					element, err = element.Add(g)
					if err != nil {
						panic(err)
					}
					element, err = element.Add(g)
					if err != nil {
						panic(err)
					}
				}
				if k&0x4 != 0 {
					element = element.Neg()
				}
				BasesLookup[i][j][k] = element
			}
		}
	}
	domainSep = []bool{false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, false, true, false, false, false, false, true, true, false, false, true, false, false, false, true, true, false, false, false, false, false, false, true, true, false, false, false, true, false, true, false, true, false, false, false, false, false, true, false, false, true, false, false, false, false, true, false, false, false, false, true, false, false, true, true, false, true, true, true, true, false, true, true, false, false, true, false, true, false, true, true, false, true, true, false, false, false, true, false, false, false, false, false, true}
}
