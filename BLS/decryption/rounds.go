// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"github.com/Safulet/tss-lib-private/v2/BLS/keygen"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	TaskName = "BLS-decryption"
)

type (
	base struct {
		*tss.Parameters

		temp localTempData

		key keygen.LocalPartySaveData

		// outbound messaging
		out        chan<- tss.Message
		end        chan<- DecryptedData
		ok         []bool // `ok` tracks parties which have been verified by Update()
		started    bool
		number     int
		isFinished bool
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
)

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

func (round *base) SetStarted(status bool) {
	round.started = status
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
	round.isFinished = false
}

func (round *base) IsFinished() bool {
	return round.isFinished
}
