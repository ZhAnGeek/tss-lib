// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/commitments"
	zkpenc "github.com/Safulet/tss-lib-private/crypto/zkp/enc"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/trace"
)

func (round *round3) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round3")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round3")

	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	round.temp.Kjs[i] = round.temp.pointKi
	// check proofs
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

			ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
			msg := round.temp.signRound2Messages[j]
			r2msg := msg.Content().(*SignRound2Message1)
			d := r2msg.UnmarshalKDeCommitment()
			cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.kjs[j], D: d}
			ok, coordinates := cmtDeCmt.DeCommit(ctx, 2)
			if !ok {
				errChs <- round.WrapError(errors.New("de-commitment verify failed"))
				return
			}
			if len(coordinates) != 2 {
				errChs <- round.WrapError(errors.New("length of de-commitment should be 2"))
				return
			}

			pointKj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
			if err != nil {
				errChs <- round.WrapError(errors.Wrapf(err, "NewECPoint(Dj)"), Pj)
				return
			}
			proofK, err := r2msg.UnmarshalZKProofK(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to unmarshal Dj proof"), Pj)
				return
			}
			ok = proofK.Verify(ctx, ContextJ, pointKj, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to prove Dj"), Pj)
				return
			}
			round.temp.Kjs[j] = pointKj
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	BigKsSum := round.temp.pointKi
	for j, Pj := range round.Parties().IDs() {
		if i == j {
			continue
		}
		var err error
		BigKsSum, err = BigKsSum.Add(round.temp.Kjs[j])
		if err != nil {
			return round.WrapError(errors.New("error in computing Ri"), Pj)
		}
	}

	// compute challenge
	// bigKs sum le is ok
	mHashKXBytes := append(round.temp.mHash, common.ReverseBytes(BigKsSum.X().Bytes())...)
	e := sha256.Sum256(mHashKXBytes)
	round.temp.e = new(big.Int).SetBytes(common.ReverseBytes(e[:]))

	tInverse := new(big.Int).ModInverse(new(big.Int).SetInt64(int64(round.Params().PartyCount())), round.EC().Params().N)
	modN := common.ModInt(round.EC().Params().N)

	// kshare = ki - e/t mod n
	kshare := modN.Sub(round.temp.ki, modN.Mul(round.temp.e, tInverse))
	Pi := round.PartyID()

	K, KNonce, err := round.key.PaillierSK.EncryptAndReturnRandomness(kshare)
	if err != nil {
		return round.WrapError(fmt.Errorf("paillier encryption failed"), Pi)
	}

	wi := round.temp.wi
	if round.temp.KeyDerivationDelta != nil {
		wi = modN.Mul(round.temp.wi, round.temp.KeyDerivationDelta)
	}
	X, XNonce, err := round.key.PaillierSK.EncryptAndReturnRandomness(wi)
	if err != nil {
		return round.WrapError(fmt.Errorf("paillier encryption failed"), Pi)
	}
	round.temp.KNonce = KNonce
	round.temp.K = K
	round.temp.KShare = kshare

	round.temp.XNonce = XNonce
	round.temp.X = X
	round.temp.XShare = wi

	round.temp.pubKeyDelta = round.key.PubKey
	if round.temp.KeyDerivationDelta != nil {
		KeyDerivationDeltaInverse := modN.ModInverse(round.temp.KeyDerivationDelta)
		round.temp.pubKeyDelta = round.key.PubKey.ScalarMult(KeyDerivationDeltaInverse)
	}

	r3msg1 := NewSignRound3Message1(round.PartyID(), K, X)
	round.out <- r3msg1

	round.temp.signRound3Messages[i] = r3msg1

	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg = sync.WaitGroup{}
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.ssid = ssid
	ContextI := append(ssid, big.NewInt(int64(i)).Bytes()...)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			proof, err := zkpenc.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, K, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], kshare, KNonce, rejectionSample)
			if err != nil {
				errChs <- round.WrapError(fmt.Errorf("ProofEnc failed: %v", err), Pi)
				return
			}

			r3msg2 := NewSignRound3Message2(Pj, round.PartyID(), proof)
			round.out <- r3msg2
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}
	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		r3msg2 := round.temp.signRound3Messages2[j]
		if r3msg2 == nil || !round.CanAccept(r3msg2) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message1); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound3Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}