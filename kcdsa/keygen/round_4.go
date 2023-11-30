// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

func (round *round4) Start(ctx context.Context) *tss.Error {
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
	Pi := round.PartyID()
	round.ok[i] = true

	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			XSharej := round.temp.r3msgBigXShare[j]
			ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))

			XD := round.temp.r3msgRXD[j]
			XF := round.temp.r3msgRXF[j]
			proofAffgDelta := round.temp.r3msgRXProof[j]
			ok := proofAffgDelta.Verify(ctx, ContextJ, round.EC(), &round.save.PaillierSK.PublicKey, round.save.PaillierPKs[j], round.save.PaillierSK.N, round.save.H1i, round.save.H2i, round.temp.R, XD, XF, XSharej, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg delta"), Pj)
				return
			}
			AlphaX, err := round.save.PaillierSK.Decrypt(XD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"), Pi)
				return
			}
			round.temp.RXShareAlphas[j] = AlphaX

			proofLogstar := round.temp.r3msgProofLogstar[j]
			Xj := round.temp.r1msg1X[j]
			ok = proofLogstar.Verify(ctx, ContextJ, round.EC(), round.save.PaillierPKs[j], Xj, XSharej, g, round.save.PaillierSK.N, round.save.H1i, round.save.H2i, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify logstar"), Pj)
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
		return round.WrapError(errors.New("round3: mta verify failed"), culprits...)
	}

	BigX := round.temp.BigXShare
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		BigXShare := round.temp.r3msgBigXShare[j]
		var err error
		BigX, err = BigX.Add(BigXShare)
		if err != nil {
			return round.WrapError(errors.New("round3: failed to collect BigX"))
		}
	}
	round.temp.BigXAll = BigX
	BigRXShare := BigX.ScalarMult(round.temp.RShare)
	round.temp.BigRXShare = BigRXShare

	modN := common.ModInt(round.EC().Params().N)
	RXShare := modN.Mul(round.temp.RShare, round.temp.XShare)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		RXShare = modN.Add(RXShare, round.temp.RXShareAlphas[j])
		RXShare = modN.Add(RXShare, round.temp.RXShareBetas[j])
	}

	round.temp.RXShare = RXShare
	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			ProofLogstar, err := zkplogstar.NewProof(ctx, ContextI, round.EC(), &round.save.PaillierSK.PublicKey, round.temp.R, BigRXShare, BigX, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j], round.temp.RShare, round.temp.RNonce, rejectionSample)
			if err != nil {
				errChs <- round.WrapError(errors.New("proofLogStar generation failed"), Pi)
				return
			}
			r4msg := NewKGRound4Message1(Pj, round.PartyID(), RXShare, BigRXShare, ProofLogstar)
			round.out <- r4msg
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound4Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.r4msgRXShare {
		if round.ok[j] {
			continue
		}
		if msg == nil || round.temp.r4msgBigRXShare[j] == nil || round.temp.r4msgProofLogstars[j] == nil {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round_out{round}
}
