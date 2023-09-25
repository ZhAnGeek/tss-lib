// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// pairing-based threshold signature is deterministic multiparty signature protocol

package encryption

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/BLS/keygen"
	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the signing part of the pairing-based threshold signature spec on BLS12381G2
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, end chan<- EncryptedData) tss.Round {
	return &round1{
		&base{params, key, temp, end, make([]bool, len(params.Parties().IDs())), false, 1}}
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

	var totalPK, suite []byte
	if tss.SameCurve(round.EC(), tss.Bls12381G2()) {
		suite = bls12381.GetBLSSignatureSuiteG1()
		totalPK = make([]byte, 192)
		round.key.PubKey.X().FillBytes(totalPK[:96])
		round.key.PubKey.Y().FillBytes(totalPK[96:])
	} else if tss.SameCurve(round.EC(), tss.Bls12381G1()) {
		suite = bls12381.GetBLSSignatureSuiteG2()
		totalPK = make([]byte, 96)
		round.key.PubKey.X().FillBytes(totalPK[:48])
		round.key.PubKey.Y().FillBytes(totalPK[48:])
	}
	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	encryptedResult, err := bls12381.Encrypt(suite, totalPK, round.temp.m)

	if err != nil {
		return round.WrapError(err)
	}

	round.end <- EncryptedData{CipherText: encryptedResult}
	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *round1) CanAccept(_ tss.ParsedMessage) bool {
	return true
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return nil
}
