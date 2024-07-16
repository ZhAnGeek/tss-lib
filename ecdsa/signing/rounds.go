// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/presigning"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	TaskName = "ecdsa-signing"
)

type (
	base struct {
		*tss.Parameters
		key        *keygen.LocalPartySaveData
		predata    *presigning.PreSignatureData
		data       *common.SignatureData
		temp       *localTempData
		out        chan<- tss.Message
		end        chan<- *common.SignatureData
		dump       chan<- *LocalDumpPB
		ok         []bool // `ok` tracks parties which have been verified by Update()
		started    bool
		number     int
		isFinished bool
	}
	sign1 struct {
		*base
	}
	sign2 struct {
		*sign1
	}

	// identification rounds
	identification3 struct {
		*sign2
	}
	identification4 struct {
		*identification3
	}
)

var (
	_ tss.Round = (*sign1)(nil)
	_ tss.Round = (*sign2)(nil)
	_ tss.Round = (*identification3)(nil)
	_ tss.Round = (*identification4)(nil)
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
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().B, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                                                // parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, round.key.NTildej...)            // NTilde
	ssidList = append(ssidList, round.key.H1j...)                // h1
	ssidList = append(ssidList, round.key.H2j...)                // h2
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.SsidNonce)
	ssid := common.SHA512_256i(ctx, ssidList...).Bytes()

	return ssid, nil
}

func (round *base) IsFinished() bool {
	return round.isFinished
}
