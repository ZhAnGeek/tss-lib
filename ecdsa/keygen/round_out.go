// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/tss"
)

func (round *roundout) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	wg := sync.WaitGroup{}
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ContextJ := append(round.temp.RidAllBz, big.NewInt(int64(j)).Bytes()[:]...)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			ok := round.temp.r4msgpfsch[j].Verify(ContextJ, round.save.BigXj[j])
			if !ok || !round.temp.r4msgpfsch[j].A.Equals(round.temp.r2msgAs[j]) {
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

	round.end <- *round.save

	return nil
}

func (round *roundout) CanAccept(msg tss.ParsedMessage) bool {
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