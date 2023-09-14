// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"bytes"
	"context"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/pkg/errors"
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
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	shareDecryptBytes := make([][]byte, 0)

	for _, i := range round.temp.shares {
		iBytes := make([]byte, 288)
		iBytes = i.FillBytes(iBytes)
		shareDecryptBytes = append(shareDecryptBytes, iBytes)
	}

	subPubKeysG2 := make([]*bls.PointG2, 0)
	if bytes.Compare(round.temp.suite, bls12381.GetBLSSignatureSuiteG1()) == 0 {
		for _, xj := range round.temp.wj {
			g2SubPubKey, err := bls12381.FromIntToPointG2(xj.X(), xj.Y())
			if err != nil {
				return round.WrapError(err)
			}
			subPubKeysG2 = append(subPubKeysG2, g2SubPubKey)
		}
	}

	subPubKeysG1 := make([]*bls.PointG1, 0)
	if bytes.Compare(round.temp.suite, bls12381.GetBLSSignatureSuiteG2()) == 0 {
		for _, xj := range round.temp.wj {
			g1SubPubKey, err := bls12381.FromIntToPointG1(xj.X(), xj.Y())
			if err != nil {
				return round.WrapError(err)
			}
			subPubKeysG1 = append(subPubKeysG1, g1SubPubKey)
		}
	}

	clearTextBytes, err := bls12381.Decrypt(round.temp.suite, shareDecryptBytes, round.temp.m, subPubKeysG2, subPubKeysG1)

	if err != nil {
		return round.WrapError(err)
	}

	round.end <- DecryptedData{ClearText: clearTextBytes}
	return nil
}

func (round *round2) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *round2) CanAccept(_ tss.ParsedMessage) bool {
	return true
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return nil
}
