// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keyshare_affine_transform

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"go.opentelemetry.io/otel/trace"
)

func (round *round4) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round5")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round5")

	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	wg := sync.WaitGroup{}
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ContextJ := common.AppendBigIntToBytesSlice(round.temp.RidAllBz, big.NewInt(int64(j)))
			ok := round.temp.r3msgpfsch[j].Verify(ctx, ContextJ, round.save.BigXj[j], rejectionSample)
			if !ok || !round.temp.r3msgpfsch[j].A.Equals(round.temp.r2msgAs[j]) {
				errChs <- round.WrapError(errors.New("proofSch verify failed"), Pj)
			}
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("round_out: proofSch verify failed"), culprits...)
	}
	round.isFinished = true
	round.end <- round.save

	return nil
}

func (round *round4) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
