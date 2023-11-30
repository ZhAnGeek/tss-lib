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
	"github.com/Safulet/tss-lib-private/crypto/mta"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"github.com/pkg/errors"
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
	round.ok[i] = true
	Pi := round.PartyID()

	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	BigXShare := crypto.ScalarBaseMult(round.Params().EC(), round.temp.XShare)
	round.temp.BigXShare = BigXShare
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			message := round.temp.signRound3Messages[j].Content().(*SignRound3Message1)
			Kj := message.UnmarshalK()
			round.temp.Ks[j] = Kj

			encProofMessage := round.temp.signRound3Messages2[j].Content().(*SignRound3Message2)
			proof, err := encProofMessage.UnmarshalEncProof()
			if err != nil {
				errChs <- round.WrapError(errors.New("proofEnc verify failed"), Pj)
				return
			}
			ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
			ok := proof.Verify(ctx, ContextJ, round.EC(), round.key.PaillierPKs[j], round.key.PaillierSK.N, round.key.H1i, round.key.H2i, Kj, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("proofEnc verify failed"), Pj)
				return
			}

			kxMta, err := mta.NewMtA(ctx, ContextI, round.EC(), Kj, round.temp.XShare, BigXShare, round.key.PaillierPKs[j], &round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], rejectionSample)
			if err != nil {
				errChs <- round.WrapError(errors.New("kxMtA failed"), Pi)
				return
			}

			ProofLogstar, err := zkplogstar.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, round.temp.X, BigXShare, g, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.XShare, round.temp.XNonce, rejectionSample)
			if err != nil {
				errChs <- round.WrapError(errors.New("proofLogStar failed"), Pi)
				return
			}

			r4msg := NewSignRound4Message1(Pj, round.PartyID(), BigXShare, kxMta.Dji, kxMta.Fji, kxMta.Proofji, ProofLogstar)
			round.out <- r4msg

			round.temp.KXShareBetas[j] = kxMta.Beta
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	return nil
}

func (round *round4) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound4Messages {
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

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
