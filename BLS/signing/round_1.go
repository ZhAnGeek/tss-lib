// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// pairing-based threshold signature is deterministic multiparty signature protocol

package signing

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/BLS/keygen"
	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the signing part of the pairing-based threshold signature spec on BLS12381
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
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

	// sign message with private key share
	pM := bls12381.Sign(round.temp.suite, round.temp.wi.Bytes(), round.temp.m)
	round.temp.sig[i] = new(big.Int).SetBytes(pM)

	r1msg := NewSignRound1Message(round.PartyID(), new(big.Int).SetBytes(pM))
	round.temp.signRound1Messages[i] = r1msg
	round.out <- r1msg

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
	BigXs := round.key.BigXj

	modN := common.ModInt(round.EC().Params().N)
	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		xi = modN.Add(xi, round.temp.KeyDerivationDelta)
		pkDelta := crypto.ScalarBaseMult(round.EC(), round.temp.KeyDerivationDelta)
		round.temp.pkDelta = pkDelta
		for j := range BigXs {
			point, err := BigXs[j].Add(pkDelta)
			if err != nil {
				return err
			}
			BigXs[j] = point
		}
	}

	if round.Threshold()+1 > len(ks) {
		// TODO: this should not panic
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi, BigWs := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs)

	round.temp.wi = wi
	round.temp.BigWs = BigWs
	return nil
}
