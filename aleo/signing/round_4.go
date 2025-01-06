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

	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon2"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func (round *round4) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	_, span := tracer.StartWithFuncSpan(ctx)
	defer span.End()

	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// verify proofs and combine tvk
	tvk := round.temp.tvkShare
	pointG := crypto.ScalarBaseMult(round.EC(), common.One)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound3Messages[j]
		r3msg := msg.Content().(*SignRound3Message)
		shareList, err := r3msg.UnmarshalShareList(round.EC())
		if err != nil {
			return round.WrapError(err, Pj)
		}
		proofList, err := r3msg.UnmarshalProofList()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		// tvk
		share := shareList[0]
		tvk, err = share.Add(tvk)
		if err != nil {
			return round.WrapError(err, Pj)
		}
		proof := proofList[0]
		ok := proof.Verify(ctx, ContextJ, round.EC(), pointG, round.temp.childAddr,
			round.temp.Rjs[j], share, common.RejectionSample)
		if !ok {
			return round.WrapError(errors.New("proof verify failed"), Pj)
		}

		// Bs and gammas
		offset := 1
		for k, pointU := range round.temp.pointUs {
			// B
			round.temp.Bs[k], err = shareList[offset].Add(round.temp.Bs[k])
			if err != nil {
				return round.WrapError(err, Pj)
			}
			ok = proofList[offset].Verify(ctx, ContextJ, round.EC(), pointG, pointU,
				round.temp.Rjs[j], shareList[offset], common.RejectionSample)
			if !ok {
				return round.WrapError(errors.New("proof verify failed"), Pj)
			}
			offset += 1
			// gamma
			round.temp.gammas[k], err = shareList[offset].Add(round.temp.gammas[k])
			if err != nil {
				return round.WrapError(err, Pj)
			}
			ok = proofList[offset].Verify(ctx, ContextJ, round.EC(), pointG, pointU,
				round.temp.bigW1s[j], shareList[offset], common.RejectionSample)
			if !ok {
				return round.WrapError(errors.New("proof verify failed"), Pj)
			}
			offset += 1
		}
	}
	round.temp.tvk = tvk

	tcm := poseidon2.HashPSD2([]*big.Int{round.temp.tvk.X()})
	scm := poseidon2.HashPSD2([]*big.Int{round.temp.childAddr.X(), round.temp.tvk.X()})
	challenge := ComputeChallenge(round.temp.tvk.X(), round.temp.R, round.temp.childPkSig, round.temp.childPrSig, round.temp.signInputs)
	modN := common.ModInt(round.EC().Params().N)
	round.temp.challenge = challenge
	round.temp.tcm = tcm
	round.temp.scm = scm

	responseShare := modN.Sub(round.temp.ri, modN.Mul(challenge, round.temp.w1i))
	round.temp.responseShare = responseShare
	r4msg := NewSignRound4Message(round.PartyID(), responseShare)
	round.out <- r4msg

	round.isFinished = true
	return nil
}

func (round *round4) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
