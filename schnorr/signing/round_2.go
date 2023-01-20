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

	"github.com/Safulet/tss-lib-private/common"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/schnorr/keygen"
	"github.com/Safulet/tss-lib-private/tss"
)

// round 2 represents round 2 of the signing part of the Schnorr TSS spec
func newRound2(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round2{&round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}}
}

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// 1. store r1 message pieces
	for j, msg := range round.temp.signRound1Messages {
		r1msg := msg.Content().(*SignRound1Message)
		round.temp.cjs[j] = r1msg.UnmarshalCommitment()
	}

	// 2. compute Schnorr prove
	proofD, err := zkpsch.NewProof(ContextI, round.temp.pointDi, round.temp.di)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	proofE, err := zkpsch.NewProof(ContextI, round.temp.pointEi, round.temp.ei)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3. BROADCAST de-commitments of Shamir poly*G and Schnorr prove
	r2msg2 := NewSignRound2Message(round.PartyID(), round.temp.deCommit, proofD, proofE)
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
