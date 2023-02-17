// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round_out) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// count r * x
	modN := common.ModInt(new(big.Int).Set(round.EC().Params().N))
	sumRXShare := round.temp.RXShare
	bigRXShare := round.temp.BigRXShare
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		var err error
		sumRXShare = modN.Add(sumRXShare, round.temp.r4msgRXShare[j])
		bigRXShare, err = bigRXShare.Add(round.temp.r4msgBigRXShare[j])
		if err != nil {
			return round.WrapError(errors.New("can not add rx share"))
		}
	}
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	bigRXShareCount := g.ScalarMult(sumRXShare)
	if !bigRXShare.Equals(bigRXShareCount) {
		return round.WrapError(errors.New("share not equal failed"))
	}

	RXModuloInverse := new(big.Int).ModInverse(sumRXShare, round.EC().Params().N)

	// count (r * x) ^ -1 * r * G
	pubkey := round.save.BigR.ScalarMult(RXModuloInverse)
	round.save.PubKey = pubkey

	// not negative needs to negate
	needsNeg := round.save.PubKey.Y().Bit(0) != 1
	// round.save.PubKey = PubKey
	round.save.Xi = new(big.Int).Mod(round.temp.xi, round.EC().Params().N)
	if needsNeg {
		xi2 := new(big.Int).Sub(round.EC().Params().N, round.temp.xi)
		round.save.Xi = new(big.Int).Mod(xi2, round.EC().Params().N)
	}

	for j, Pj := range round.save.BigXj {
		BigXj := Pj
		if needsNeg {
			Yj2 := new(big.Int).Sub(round.EC().Params().P, BigXj.Y())
			BigXj2, err := crypto.NewECPoint(round.EC(), BigXj.X(), Yj2)
			if err != nil {
				return round.WrapError(err)
			}
			round.save.BigXj[j] = BigXj2
		}
	}

	round.end <- *round.save
	return nil
}

func (round *round_out) CanAccept(msg tss.ParsedMessage) bool {
	return true
}

func (round *round_out) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *round_out) NextRound() tss.Round {
	return nil // finished!
}
