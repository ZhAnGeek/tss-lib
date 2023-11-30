// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/trace"
)

func (round *round5) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round5")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round5")

	round.number = 5
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
	Pi := round.PartyID()

	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())

	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			message := round.temp.signRound4Messages[j].Content().(*SignRound4Message1)
			XSharej, err := message.UnmarshalBigXShare(round.EC())
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}

			ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))

			XD := message.UnmarshalDjiKX()
			XF := message.UnmarshalFjiKX()
			proofAffgDelta, err := message.UnmarshalAffgProofRX(round.EC())
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			ok := proofAffgDelta.Verify(ctx, ContextJ, round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.PaillierSK.N, round.key.H1i, round.key.H2i, round.temp.K, XD, XF, XSharej, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg delta"), Pj)
				return
			}
			AlphaX, err := round.key.PaillierSK.Decrypt(XD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"), Pi)
				return
			}
			round.temp.KXShareAlphas[j] = AlphaX

			proofLogstar, err := message.UnmarshalLogstarProof(round.EC())
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"), Pi)
				return
			}
			messageR3 := round.temp.signRound3Messages[j].Content().(*SignRound3Message1)
			Xj := messageR3.UnmarshalX()
			ok = proofLogstar.Verify(ctx, ContextJ, round.EC(), round.key.PaillierPKs[j], Xj, XSharej, g, round.key.PaillierSK.N, round.key.H1i, round.key.H2i, rejectionSample)
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
		message := round.temp.signRound4Messages[j].Content().(*SignRound4Message1)
		XSharej, err := message.UnmarshalBigXShare(round.EC())
		BigX, err = BigX.Add(XSharej)
		if err != nil {
			return round.WrapError(errors.New("round3: failed to collect BigGamma"))
		}
	}
	round.temp.BigXAll = BigX
	BigKXShare := BigX.ScalarMult(round.temp.KShare)
	round.temp.BigKXShare = BigKXShare
	modN := common.ModInt(round.EC().Params().N)
	KXShare := modN.Mul(round.temp.KShare, round.temp.XShare)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		KXShare = modN.Add(KXShare, round.temp.KXShareAlphas[j])
		KXShare = modN.Add(KXShare, round.temp.KXShareBetas[j])
	}

	round.temp.KXShare = KXShare
	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			ProofLogstar, err := zkplogstar.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, BigKXShare, BigX, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.KShare, round.temp.KNonce, rejectionSample)
			if err != nil {
				errChs <- round.WrapError(errors.New("proofLogStar generation failed"), Pi)
				return
			}
			r5msg := NewSignRound5Message1(Pj, round.PartyID(), KXShare, BigKXShare, ProofLogstar)
			round.out <- r5msg
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}
	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound5Messages {
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

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound5Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
