// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package minasigning

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *finalization) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	sumZ := round.temp.zi
	modQ := common.ModInt(round.EC().Params().N)
	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		zj := r3msg.UnmarshalZi()

		LHS := crypto.ScalarBaseMult(round.EC(), zj)
		RHS, err := round.temp.Rjs[j].Add(round.temp.bigWs[j].ScalarMult(round.temp.c))
		if err != nil {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		if !LHS.Equals(RHS) {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		sumZ = modQ.Add(sumZ, zj)
	}

	// save the signature for final output
	round.data.R = round.temp.R.X().Bytes()
	round.data.S = sumZ.Bytes()
	round.data.Signature = append(round.temp.R.X().Bytes(), sumZ.Bytes()...)
	round.data.M = round.temp.m

	err := MinaSchnorrVerify(round.key.PubKey, round.temp.m, round.data.Signature)
	if err != nil {
		return round.WrapError(errors.New("signature verification failed"))
	}

	round.end <- *round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
