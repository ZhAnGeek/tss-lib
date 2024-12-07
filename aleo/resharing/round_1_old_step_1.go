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

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the reshare part of the Schnorr TSS spec
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

	if !round.ReSharingParams().IsOldCommittee() {
		return nil
	}
	round.allOldOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 0. ssid
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().B, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.OldParties().IDs().Keys()...)                                                                             // old parties
	ssidList = append(ssidList, round.NewParties().IDs().Keys()...)                                                                             // new parties
	PkSigList, err := crypto.FlattenECPoints(round.input.PkSigShares)
	if err != nil {
		return round.WrapError(errors.New("read BigXj failed"), Pi)
	}
	PrSigList, err := crypto.FlattenECPoints(round.input.PrSigShares)
	if err != nil {
		return round.WrapError(errors.New("read BigXj failed"), Pi)
	}
	ssidList = append(ssidList, PkSigList...) // BigXj
	ssidList = append(ssidList, PrSigList...) // BigXj

	ssid := common.SHA512_256i(ctx, ssidList...).Bytes()

	// 1. PrepareForSigning() -> w_i
	xi, ks, bigXj := round.input.SkSigShare, round.input.Ks, round.input.PkSigShares
	if round.Threshold()+1 > len(ks) {
		return round.WrapError(fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks)), round.PartyID())
	}
	newKs := round.NewParties().IDs().Keys()
	wi, _ := crypto.PrepareForSigning(round.Params().EC(), i, len(round.OldParties().IDs()), xi, ks, bigXj)

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

	ContextI := append(ssid, big.NewInt(int64(i)).Bytes()...)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	proof, err := zkpsch.NewProof(ctx, ContextI, vi[0], wi, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 1. PrepareForSigning() -> w_i
	x2i, ks2, bigXj2 := round.input.RSigShare, round.input.Ks, round.input.PrSigShares
	if round.Threshold()+1 > len(ks) {
		return round.WrapError(fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks)), round.PartyID())
	}
	wi2, _ := crypto.PrepareForSigning(round.Params().EC(), i, len(round.OldParties().IDs()), x2i, ks2, bigXj2)

	// 2.
	vi2, shares2, err := vss.Create(round.Params().EC(), round.NewThreshold(), wi2, newKs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis2, err := crypto.FlattenECPoints(vi2)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	vCmt2 := commitments.NewHashCommitment(ctx, flatVis2...)
	proof2, err := zkpsch.NewProof(ctx, ContextI, vi2[0], wi2, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 4. populate temp data
	round.temp.SSID = ssid

	round.temp.VD = vCmt.D
	round.temp.NewShares = shares
	round.temp.proof = proof

	round.temp.RVD = vCmt2.D
	round.temp.RNewShares = shares2
	round.temp.Rproof = proof2

	// 5. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1Message(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.input.PkSig, vCmt.C, round.input.PrSig, vCmt2.C, ssid)

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
		candidate, err := r1msg.UnmarshalSigPubKey(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the schnorr pub key"), msg.GetFrom())
		}
		if round.save.PkSig != nil &&
			!candidate.Equals(round.save.PkSig) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("schnorr pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.PkSig = candidate

		// save the schnorr pub received from the old committee
		rCandidate, err := r1msg.UnmarshalRPubKey(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the schnorr pub key"), msg.GetFrom())
		}
		if round.save.PrSig != nil &&
			!rCandidate.Equals(round.save.PrSig) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("schnorr pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.PrSig = rCandidate
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
