// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keyshare_affine_transform

import (
	"context"
	"errors"
	"sync"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"go.opentelemetry.io/otel/trace"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round2")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round2")

	round.number = 2
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	{
		msg1 := NewKTRound2Message1(round.PartyID(), round.temp.vs, round.temp.Ai, round.temp.rid, round.temp.cmtRandomness)
		round.out <- msg1
	}

	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			Cij, err := round.key.PaillierPKs[j].Encrypt(round.temp.shares[j].Share)
			if err != nil {
				errChs <- round.WrapError(errors.New("encrypt error"), Pi)
			}

			msg2 := NewKTRound2Message2(Pj, Pi, Cij)
			round.out <- msg2
		}(j, Pj)

	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KTRound2Message1); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KTRound2Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.r2msgVss {
		if round.ok[j] {
			continue
		}
		if msg == nil ||
			round.temp.r2msgAs[j] == nil ||
			round.temp.r2msgCmtRandomness[j] == nil ||
			round.temp.r2msgRids[j] == nil || round.temp.r2msgxij[j] == nil {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
