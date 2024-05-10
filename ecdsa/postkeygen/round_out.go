// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

func (round *roundout4) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round4")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round4")

	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
	wg := sync.WaitGroup{}
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			facProof := round.temp.ProofFacs[j]
			if ok := facProof.Verify(ctx, ContextI, round.EC(), round.save.NTildej[j],
				round.save.PaillierSK.N, round.save.H1i, round.save.H2i, rejectionSample); !ok {
				errChs <- round.WrapError(errors.New("pj fac proof verified fail"), Pj)
				return
			}
		}(j, Pj)
	}
	round.isFinished = true
	round.end <- round.save

	return nil
}

func (round *roundout4) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *roundout4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *roundout4) NextRound() tss.Round {
	return nil // finished!
}
