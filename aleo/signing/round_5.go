// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func (round *round5) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	_, span := tracer.StartWithFuncSpan(ctx)
	defer span.End()

	round.number = 5
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	response := round.temp.responseShare
	modQ := common.ModInt(round.EC().Params().N)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		round.ok[j] = true
		r4msg := round.temp.signRound4Messages[j].Content().(*SignRound4Message)
		zj := r4msg.UnmarshalResponseShare()
		response = modQ.Add(response, zj)
	}
	if response.Cmp(common.Zero) == 0 {
		return round.WrapError(errors.New("response cannot be zero"))
	}

	ok := Verify(round.temp.childPkSig, round.temp.childPrSig, round.temp.tvk.X(), round.temp.tcm, round.temp.challenge, response, round.temp.signInputs)
	if !ok {
		return round.WrapError(errors.New("request verification failed"))
	}

	requestOut := NewRequestOut(round.temp.challenge, response, round.temp.skTag, round.temp.tvk.X(), round.temp.tcm, round.temp.scm)
	round.end <- requestOut

	round.isFinished = true
	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
	// ret := true
	// for j, msg := range round.temp.signRound4Messages {
	// 	if round.ok[j] {
	// 		continue
	// 	}
	// 	if msg == nil || !round.CanAccept(msg) {
	// 		ret = false
	// 		continue
	// 	}
	// 	round.ok[j] = true
	// }
	// return ret, nil
}

func (round *round5) CanAccept(_ tss.ParsedMessage) bool {
	return false
}

func (round *round5) NextRound() tss.Round {
	return nil // finished!
	// round.started = false
	// return &round5{round}
}
