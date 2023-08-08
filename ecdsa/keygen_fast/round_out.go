// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen_fast

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/tss"
)

func (round *roundout) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
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

	round.end <- *round.save

	return nil
}

func (round *roundout) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *roundout) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *roundout) NextRound() tss.Round {
	return nil // finished!
}
