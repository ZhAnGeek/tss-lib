// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"context"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/tss"
)

const (
	TaskName = "ecdsa-postkeygen"
)

type (
	base struct {
		*tss.Parameters
		save    *keygen.LocalPartySaveData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- keygen.LocalPartySaveData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	roundout struct {
		*round3
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*roundout)(nil)
)

// ----- //
func (round *base) SetStarted(status bool) {
	round.started = status
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
}

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

// get ssid from local params
func (round *base) getSSID(ctx context.Context) ([]byte, error) {
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                         // parties
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)
	// round number
	ssid := common.SHA512_256i(ctx, ssidList...).Bytes()

	return ssid, nil
}