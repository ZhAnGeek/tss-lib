// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postsigning

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	_, span := tracer.StartWithFuncSpan(ctx)
	defer span.End()

	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	response := round.temp.zi
	modQ := common.ModInt(round.EC().Params().N)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		round.ok[j] = true
		r1msg := round.temp.psignRound1Messages[j].Content().(*PSignRound1Message)
		zj := r1msg.UnmarshalResponseShare()
		response = modQ.Add(response, zj)
	}
	if response.Cmp(common.Zero) == 0 {
		return round.WrapError(errors.New("response cannot be zero"))
	}
	log.Info(ctx, "response: %s", response)

	round.isFinished = true
	request := NewRequestData(round.temp.challenge, response)
	round.end <- request

	return nil
}

func (round *round2) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round2) NextRound() tss.Round {
	return nil // finished!
}
