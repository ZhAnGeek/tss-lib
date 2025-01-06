// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// pairing-based threshold signature is deterministic multiparty signature protocol

package decryption

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/BLS/keygen"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the signing part of the pairing-based threshold signature spec on G2Curve
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- DecryptedData) tss.Round {
	return &round1{
		&base{params, *temp, *key, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
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
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	share, err := bls12381.DecryptShare(round.temp.suite, round.temp.wi.Bytes(), round.temp.m)

	if err != nil {
		return round.WrapError(err)
	}
	round.temp.shares[i] = new(big.Int).SetBytes(share)
	r1msg := NewDecryptionRound1Message(round.PartyID(), new(big.Int).SetBytes(share))

	round.temp.decryptionRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.decryptionRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DecryptionRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //
func (round *round1) prepare() error {
	i := round.PartyID().Index

	if tss.SameCurve(round.EC(), tss.Bls12381G2()) {
		round.temp.suite = bls12381.GetBLSSignatureSuiteG1()
		round.temp.PublicKeySize = bls12381.PublicKeySizeG2
		round.temp.SignatureSize = bls12381.SignatureSizeG1
	} else if tss.SameCurve(round.EC(), tss.Bls12381G1()) {
		round.temp.suite = bls12381.GetBLSSignatureSuiteG2()
		round.temp.PublicKeySize = bls12381.PublicKeySizeG1
		round.temp.SignatureSize = bls12381.SignatureSizeG2
	}

	xi := round.key.Xi
	ks := round.key.Ks
	kj := round.key.BigXj

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi, wj := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, kj)

	round.temp.wi = wi
	round.temp.wj = wj
	return nil
}
