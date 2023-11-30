// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"bytes"
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	zkpmod "github.com/Safulet/tss-lib-private/crypto/zkp/mod"
	zkpprm "github.com/Safulet/tss-lib-private/crypto/zkp/prm"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round2")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round2")

	round.number = 2
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	// check consistency of SSID
	r1msg := round.temp.dgRound1Messages[0].Content().(*DGRound1Message)
	SSID := r1msg.UnmarshalSSID()
	for j, Pj := range round.OldParties().IDs() {
		if j == 0 {
			continue
		}
		r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		SSIDj := r1msg.UnmarshalSSID()
		if !bytes.Equal(SSID, SSIDj) {
			return round.WrapError(errors.New("ssid mismatch"), Pj)
		}
	}
	round.temp.ssid = SSID

	// 1. "broadcast" "ACK" members of the OLD committee
	r2msg := NewDGRound2Message(round.OldParties().IDs().Exclude(round.PartyID()), Pi)
	round.temp.dgRound2Messages[i] = r2msg
	round.out <- r2msg

	Phi := new(big.Int).Mul(new(big.Int).Lsh(round.save.P, 1), new(big.Int).Lsh(round.save.Q, 1))
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	proofPrm, err := zkpprm.NewProof(ctx, ContextI, round.save.H1i, round.save.H2i, round.save.PaillierSK.N, Phi, round.save.Beta)
	if err != nil {
		return round.WrapError(errors.New("create proofPrm failed"), Pi)
	}

	one := new(big.Int).SetUint64(1)
	// Fig 5. Round 3.2 / Fig 6. Round 3.2 proofs
	SP := new(big.Int).Add(new(big.Int).Lsh(round.save.P, 1), one)
	SQ := new(big.Int).Add(new(big.Int).Lsh(round.save.Q, 1), one)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	proofMod, err := zkpmod.NewProof(ctx, ContextI, round.save.PaillierSK.N, SP, SQ, rejectionSample)
	if err != nil {
		return round.WrapError(errors.New("create proofMod failed"), Pi)
	}

	r2msg2 := NewDGRound2Message2(round.NewParties().IDs().Exclude(round.PartyID()), Pi, proofPrm, proofMod)
	round.temp.dgRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if round.ReSharingParams().IsNewCommittee() {
		if _, ok := msg.Content().(*DGRound2Message2); ok {
			return msg.IsBroadcast()
		}
	}
	if round.ReSharingParams().IsOldCommittee() {
		if _, ok := msg.Content().(*DGRound2Message); ok {
			return msg.IsBroadcast()
		}
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	if round.ReSharingParams().IsOldCommittee() && round.ReSharingParameters.IsNewCommittee() {
		// accept messages from new -> old committee
		for j, msg1 := range round.temp.dgRound2Messages {
			if round.newOK[j] {
				continue
			}
			if msg1 == nil || !round.CanAccept(msg1) {
				ret = false
				continue
			}
			// accept message from new -> committee
			msg2 := round.temp.dgRound2Message2s[j]
			if msg2 == nil || !round.CanAccept(msg2) {
				ret = false
				continue
			}
			round.newOK[j] = true
		}
	} else if round.ReSharingParams().IsOldCommittee() {
		// accept messages from new -> old committee
		for j, msg := range round.temp.dgRound2Messages {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				ret = false
				continue
			}
			round.newOK[j] = true
		}
	} else if round.ReSharingParams().IsNewCommittee() {
		// accept messages from new -> new committee
		for j, msg := range round.temp.dgRound2Message2s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				ret = false
				continue
			}
			round.newOK[j] = true
		}
	} else {
		return false, round.WrapError(errors.New("this party is not in the old or the new committee"), round.PartyID())
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
