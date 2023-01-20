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

	errors2 "github.com/pkg/errors"

	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// 1. store r1 message pieces
	for j, msg := range round.temp.signRound1Messages {
		r1msg := msg.Content().(*SignRound1Message)
		round.temp.cjs[j] = r1msg.UnmarshalCommitment()
	}

	// 2. compute Schnorr prove
	pir, err := zkpsch.NewProof(ContextI, round.temp.pointRi, round.temp.ri)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "NewZKProof(ri, pointRi)"))
	}

	// 3. BROADCAST de-commitments of Shamir poly*G and Schnorr prove
	r2msg2 := NewSignRound2Message(round.PartyID(), round.temp.deCommit, pir)
	round.temp.signRound2Messages[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
