// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

func newRound4(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *PreSignatureData, dump chan<- *LocalDumpPB) tss.Round {
	return &presignout{&presign3{&presign2{&presign1{
		&base{params, key, temp, out, end, dump, make([]bool, len(params.Parties().IDs())), false, 4, false}}}}}
}

func (round *presignout) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round4")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round4")

	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Output.1 verify proof logstar
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ContextJ := common.AppendBigIntToBytesSlice(round.temp.Ssid, big.NewInt(int64(j)))
			Kj := round.temp.R1msgK[j]
			BigDeltaSharej := round.temp.R3msgBigDeltaShare[j]
			proofLogstar := round.temp.R3msgProofLogstar[j]

			ok := proofLogstar.Verify(ctx, ContextJ, round.EC(), round.key.PaillierPKs[j], Kj, BigDeltaSharej, round.temp.BigGamma, round.key.NTildei, round.key.H1i, round.key.H2i, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("proof verify failed"), Pj)
				return
			}
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to verify proofs"), culprits...)
	}

	// Fig 7. Output.2 check equality
	modN := common.ModInt(round.EC().Params().N)
	Delta := round.temp.DeltaShare
	BigDelta := round.temp.BigDeltaShare
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		Delta = modN.Add(Delta, round.temp.R3msgDeltaShare[j])
		BigDeltaShare := round.temp.R3msgBigDeltaShare[j]
		var err error
		BigDelta, err = BigDelta.Add(BigDeltaShare)
		if err != nil {
			return round.WrapError(errors.New("round4: failed to collect BigDelta"))
		}
	}

	DeltaPoint := crypto.ScalarBaseMult(round.EC(), Delta)
	if !DeltaPoint.Equals(BigDelta) {
		return round.WrapError(errors.New("verify BigDelta failed"))
	}
	// compute the multiplicative inverse thelta mod q
	deltaInverse := modN.ModInverse(Delta)
	err := common.CheckBigIntNotNil(deltaInverse)
	if err != nil {
		return round.WrapError(err)
	}
	BigR := round.temp.BigGamma.ScalarMult(deltaInverse)

	transcript := &Transcript{}
	if round.NeedsIdentifaction() {
		transcript = &Transcript{
			K:              round.temp.K,
			R1msgK:         round.temp.R1msgK,
			ChiShareAlphas: round.temp.ChiShareAlphas,
			ChiShareBetas:  round.temp.ChiShareBetas,
			R2msgChiD:      round.temp.R2msgChiD,

			ChiMtAFs:      round.temp.ChiMtAFs,
			ChiMtADs:      round.temp.ChiMtADs,
			ChiMtADProofs: round.temp.ChiMtADProofs,
			ChiMtABetaNeg: round.temp.ChiMtABetaNeg,
			ChiMtASij:     round.temp.ChiMtASij,
			ChiMtARij:     round.temp.ChiMtARij,
		}
	}

	preSignData := NewPreSignData(i, round.temp.Ssid, BigR, round.temp.KShare, round.temp.ChiShare, transcript, round.temp.SsidNonce)
	round.isFinished = true
	round.end <- preSignData

	if round.NeedsIdentifaction() && round.dump != nil {
		du := &LocalDump{
			Temp:     round.temp,
			RoundNum: round.number + 1, // Notice, dierct restore into identification 1
			Index:    i,
		}
		duPB := NewLocalDumpPB(du.Index, du.RoundNum, du.Temp)
		round.dump <- duPB
	}

	return nil
}

func (round *presignout) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *presignout) CanAccept(_ tss.ParsedMessage) bool {
	return false
}

func (round *presignout) NextRound() tss.Round {
	round.started = false
	return nil
}
