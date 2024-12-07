// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package poseidon8

import (
	_ "embed"
	"encoding/json"
	"math/big"
)

type Constants struct {
	Values [][]*big.Int
}

var (
	// params dumped from https://github.com/AleoNet/snarkVM/blob/4965f6b64eaf283ccdf192abde6a58554245b89f/console/network/src/mainnet_v0.rs#L69
	//go:embed mds.data
	mdsBytes []byte
	//go:embed arc.data
	arcBytes []byte
)

func init() {
	var mds Constants
	err := json.Unmarshal(mdsBytes, &mds)
	if err != nil {
		panic(err)
	}
	var arc Constants
	err = json.Unmarshal(arcBytes, &arc)
	if err != nil {
		panic(err)
	}
	Mds = mds.Values
	Arc = arc.Values
}
