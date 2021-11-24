// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning

import (
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	TaskName = "presigning"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- PreSignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	presign1 struct {
		*base
	}
	presign2 struct {
		*presign1
	}
	presign3 struct {
		*presign2
	}
	presignout struct {
		*presign3
	}
)

var (
	_ tss.Round = (*presign1)(nil)
	_ tss.Round = (*presign2)(nil)
	_ tss.Round = (*presign3)(nil)
	_ tss.Round = (*presignout)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

func (round *base) Dump(dumpCh chan tss.ParsedMessage) {
	DumpMsg := NewTempDataDumpMessage(round.PartyID(), *round.temp, round.number)
	dumpCh <- DumpMsg
}
