// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	cmts "github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	"github.com/Safulet/tss-lib-private/tss"
)

// round 1 represents round 1 of the keygen part of the Schnorr TSS spec
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	round.temp.ssidNonce = new(big.Int).SetInt64(int64(0))
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.ssid = ssid

	// calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(round.Params().EC().Params().N)
	round.temp.ui = ui

	// compute the vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt := cmts.NewHashCommitment(pGFlat...)

	round.save.ShareID = ids[i]
	round.temp.vs = vs
	round.temp.shares = shares
	round.temp.deCommitPolyG = cmt.D

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), cmt.C)
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.KGCs {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}