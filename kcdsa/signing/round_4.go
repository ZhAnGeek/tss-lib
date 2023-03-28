// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/crypto/mta"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	"github.com/pkg/errors"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round4) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

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
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			message := round.temp.signRound3Messages[j].Content().(*SignRound3Message1)
			Kj := message.UnmarshalK()

			encProofMessage := round.temp.signRound3Messages2[j].Content().(*SignRound3Message2)
			proof, err := encProofMessage.UnmarshalEncProof()
			if err != nil {
				errChs <- round.WrapError(errors.New("verify enc proof failed"), Pi)
				return
			}
			if err != nil {
				errChs <- round.WrapError(errors.New("verify enc proof failed"), Pi)
				return
			}
			ContextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
			ok := proof.Verify(ctx, ContextJ, round.EC(), round.key.PaillierPKs[j], round.key.PaillierSK.N, round.key.H1i, round.key.H2i, Kj)
			if !ok {
				errChs <- round.WrapError(errors.New("round2: proofEnc verify failed"), Pj)
				return
			}

			kxMta, err := mta.NewMtA(ctx, ContextI, round.EC(), Kj, round.temp.XShare, BigXShare, round.key.PaillierPKs[j], &round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
			if err != nil {
				errChs <- round.WrapError(errors.New("MtADelta failed"), Pi)
				return
			}

			ProofLogstar, err := zkplogstar.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, round.temp.X, BigXShare, g, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.XShare, round.temp.XNonce)
			if err != nil {
				errChs <- round.WrapError(errors.New("prooflogstar failed"), Pi)
				return
			}

			r4msg := NewSignRound4Message1(Pj, round.PartyID(), BigXShare, kxMta.Dji, kxMta.Fji, kxMta.Proofji, ProofLogstar)
			round.out <- r4msg

			round.temp.KXShareBetas[j] = kxMta.Beta

			if round.NeedsIdentifaction() {
				// record transcript for presign identification 1
				round.temp.KXMtAFs[j] = kxMta.Fji
				round.temp.KXMtADs[j] = kxMta.Dji
				round.temp.KXMtARXProofs[j] = kxMta.Proofji
			}
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
	for j, msg := range round.temp.signRound4Messages {
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
