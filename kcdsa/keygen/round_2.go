// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	zkpenc "github.com/Safulet/tss-lib-private/crypto/zkp/enc"
	zkpfac "github.com/Safulet/tss-lib-private/crypto/zkp/fac"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

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
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())

	// Fig 7. Round 1. create proof enc
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	Pi := round.PartyID()
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		contextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			proofPrm := round.temp.ProofPrms[j]
			if ok := proofPrm.Verify(ctx, contextJ, round.save.H1j[j], round.save.H2j[j], round.save.NTildej[j]); !ok {
				errChs <- round.WrapError(fmt.Errorf("ProofMod failed"), Pj)
			}
			proofMod := round.temp.ProofMods[j]
			if ok := proofMod.Verify(ctx, contextJ, round.save.NTildej[j], rejectionSample); !ok {
				errChs <- round.WrapError(fmt.Errorf("ProofMod failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
			SP := new(big.Int).Add(new(big.Int).Lsh(round.save.LocalPreParams.P, 1), big.NewInt(1))
			SQ := new(big.Int).Add(new(big.Int).Lsh(round.save.LocalPreParams.Q, 1), big.NewInt(1))
			proofFac, err := zkpfac.NewProof(ctx, ContextJ, round.EC(), round.save.LocalPreParams.PaillierSK.N,
				round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j], SP, SQ, rejectionSample)

			proof, err := zkpenc.NewProof(ctx, ContextI, round.EC(), &round.save.PaillierSK.PublicKey, round.temp.R, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j], round.temp.RShare, round.temp.RNonce, rejectionSample)
			if err != nil {
				errChs <- round.WrapError(fmt.Errorf("ProofEnc failed: %v", err), Pi)
				return
			}

			r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), proof, proofFac, round.temp.vsRshares[j], round.temp.vsXshares[j])
			round.out <- r2msg1
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	// compute Schnorr prove
	proof, err := zkpsch.NewProof(ctx, ContextI, round.temp.vs[0], round.temp.ui, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// compute Schnorr prove
	rproof, err := zkpsch.NewProof(ctx, ContextI, round.temp.rvs[0], round.temp.ri, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// BROADCAST de-commitments of Shamir poly*G and Schnorr prove
	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.rdeCommitPolyG, rproof, round.temp.deCommitPolyG, proof)
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r2msg1SharesX {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		if round.temp.r2msg2DecommitX[j] == nil || round.temp.r2msg2ProofX[j] == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	for j, msg := range round.temp.r2msg1SharesR {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		if round.temp.r2msg2DecommitR[j] == nil || round.temp.r2msg2ProofR[j] == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
