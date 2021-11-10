// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/schnorr/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the signing part of the Schnorr TSS spec
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// 1. select di, ei
	di := common.GetRandomPositiveInt(round.EC().Params().N)
	ei := common.GetRandomPositiveInt(round.EC().Params().N)

	// 2. make commitment
	pointDi := crypto.ScalarBaseMult(round.Params().EC(), di)
	pointEi := crypto.ScalarBaseMult(round.Params().EC(), ei)
	cmt := commitments.NewHashCommitment(pointDi.X(), pointDi.Y(), pointEi.X(), pointEi.Y())

	// 3. store r1 message pieces
	round.temp.di = di
	round.temp.ei = ei
	round.temp.pointDi = pointDi
	round.temp.pointEi = pointEi
	round.temp.deCommit = cmt.D

	// 4. broadcast commitment
	r1msg2 := NewSignRound1Message(round.PartyID(), cmt.C)
	round.temp.signRound1Messages[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		// TODO: this should not panic
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks)

	round.temp.wi = wi
	return nil
}
