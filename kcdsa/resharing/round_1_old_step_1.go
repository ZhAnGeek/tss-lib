// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	"github.com/Safulet/tss-lib-private/v2/kcdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/kcdsa/signing"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the reshare part of the KCDSA TSS spec
func newRound1(params *tss.ReSharingParameters, input, save *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *keygen.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, temp, input, save, out, end, make([]bool, len(params.OldParties().IDs())), make([]bool, len(params.NewParties().IDs())), false, 1, false}}
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round1")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round1")

	round.number = 1
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	Pi := round.PartyID()
	// new party generate paillier
	if !round.ReSharingParams().IsOldCommittee() {

		var preParams *keygen.LocalPreParams
		if round.save.LocalPreParams.Validate() {
			preParams = &round.save.LocalPreParams
		} else {
			var err error
			preParams, err = keygen.GeneratePreParams(ctx, round.SafePrimeGenTimeout())
			if err != nil {
				return round.WrapError(errors.New("pre-params generation failed"), Pi)
			}
			round.save.LocalPreParams = *preParams
		}
		msg := NewDGRound1MessageNewParty(round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(), &round.save.PaillierSK.PublicKey, round.save.PaillierSK.N, round.save.H1i, round.save.H2i)
		round.out <- msg
		return nil
	}

	var err error
	// 0. ssid
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.OldParties().IDs().Keys()...)                                                      // old parties
	ssidList = append(ssidList, round.NewParties().IDs().Keys()...)                                                      // new parties
	BigXjList, err := crypto.FlattenECPoints(round.input.BigXj)
	if err != nil {
		return round.WrapError(errors.New("read BigXj failed"), Pi)
	}
	ssidList = append(ssidList, BigXjList...)           // BigXj
	ssidList = append(ssidList, round.input.NTildej...) // NCap
	ssidList = append(ssidList, round.input.H1j...)     // s
	ssidList = append(ssidList, round.input.H2j...)     // t
	ssid := common.SHA512_256i(ctx, ssidList...).Bytes()
	round.allOldOK()
	i := Pi.Index

	// 1. PrepareForSigning() -> w_i
	xi, ks := round.input.Xi, round.input.Ks
	if round.Threshold()+1 > len(ks) {
		return round.WrapError(fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks)), round.PartyID())
	}
	newKs := round.NewParties().IDs().Keys()
	wi := signing.PrepareForSigning(round.Params().EC(), i, len(round.OldParties().IDs()), xi, ks, round.input.BigXj, round.input.PubKey, round.input.BigR)

	// 2.
	vi, shares, err := vss.Create(round.Params().EC(), round.NewThreshold(), wi, newKs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	vCmt := commitments.NewHashCommitment(ctx, flatVis...)

	// 4. populate temp data
	round.temp.VD = vCmt.D
	round.temp.NewShares = shares

	// 5. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1Message(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.input.PubKey, round.input.PubKeySchnorr, vCmt.C, ssid)
	round.temp.dgRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	// accept messages from old -> new committee
	if _, ok := msg.Content().(*DGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	// only the new committee receive in this round
	if !round.ReSharingParameters.IsNewCommittee() {
		return true, nil
	}
	// accept messages from old -> new committee
	ret := true
	for j, msg := range round.temp.dgRound1Messages {
		if round.oldOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.oldOK[j] = true

		// save the schnorr pub received from the old committee
		r1msg := msg.Content().(*DGRound1Message)
		candidate, err := r1msg.UnmarshalPubKey(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the schnorr pub key"), msg.GetFrom())
		}
		if round.save.PubKey != nil &&
			!candidate.Equals(round.save.PubKey) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("kcdsa pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.PubKey = candidate

		// save the schnorr pub received from the old committee
		candidateSchnorr, err := r1msg.UnmarshalPubKeySchnorr(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the schnorr pub key"), msg.GetFrom())
		}
		if round.save.PubKeySchnorr != nil &&
			!candidateSchnorr.Equals(round.save.PubKeySchnorr) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("kcdsa pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.PubKeySchnorr = candidateSchnorr
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
