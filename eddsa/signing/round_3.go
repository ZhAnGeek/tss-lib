// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/edwards25519"
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

	// 1. init R
	Rx, Ry := round.EC().ScalarBaseMult(round.temp.ri.Bytes())

	// 2-6. compute R
	i := round.PartyID().Index
	round.ok[i] = true

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit(ctx, 2)
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		Rj = Rj.EightInvEight()
		proof, err := r2msg.UnmarshalZKProof(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		rejectionSample := tss.GetRejectionSampleFunc(round.Version())
		ok = proof.Verify(ctx, ContextJ, Rj, rejectionSample)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		Rx, Ry = round.EC().Add(Rx, Ry, Rj.X(), Rj.Y())
	}

	// Compute PubKey with Delta
	PkX, PkY := round.key.EDDSAPub.X(), round.key.EDDSAPub.Y()
	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		DeltaX, DeltaY := round.EC().ScalarBaseMult(round.temp.KeyDerivationDelta.Bytes())
		PkX, PkY = round.EC().Add(PkX, PkY, DeltaX, DeltaY)
	}
	round.temp.PKX = PkX
	round.temp.PKY = PkY

	// 7. compute lambda
	encodedPubKey := edwards25519.EcPointToEncodedBytes(round.temp.PKX, round.temp.PKY)
	encodedR := edwards25519.EcPointToEncodedBytes(Rx, Ry)

	// h = hash512(k || A || M)
	h := round.Parameters.HashFunc()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	h.Write(round.temp.m)

	var lambda [64]byte

	h.Sum(lambda[:0])
	lambdaReduced := new(big.Int).Mod(new(big.Int).SetBytes(common.ReverseBytes(lambda[:])), round.EC().Params().N)

	// 8. compute si
	modQ := common.ModInt(round.EC().Params().N)
	si := modQ.Mul(lambdaReduced, round.temp.wi)
	si = modQ.Add(si, round.temp.ri)

	// 9. store r3 message pieces
	round.temp.si = si
	round.temp.r = edwards25519.EncodedBytesToBigInt(encodedR)

	// 10. broadcast si to other parties
	r3msg := NewSignRound3Message(round.PartyID(), si)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
