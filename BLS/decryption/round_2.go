// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"context"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/pkg/errors"

	"github.com/Safulet/tss-lib-private/v2/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	shareDecryptBytes := make([][]byte, 0)

	for _, i := range round.temp.shares {
		iBytes := make([]byte, 288)
		iBytes = i.FillBytes(iBytes)
		shareDecryptBytes = append(shareDecryptBytes, iBytes)
	}

	subPubKeys := make([]*bls.PointG2, 0)
	for _, xj := range round.temp.wj {
		g2SubPubKey, err := bls12381.FromIntToPointG2(xj.X(), xj.Y())
		if err != nil {
			return round.WrapError(err)
		}
		subPubKeys = append(subPubKeys, g2SubPubKey)
	}

	clearTextBytes, err := bls12381.Decrypt(shareDecryptBytes, round.temp.m, subPubKeys)

	if err != nil {
		return round.WrapError(err)
	}

	round.end <- DecryptedData{ClearText: clearTextBytes}
	return nil
}

func (round *round2) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	return true
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return nil
}
