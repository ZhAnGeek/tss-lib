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
	"github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/schnorr/signing/btc"
	"github.com/Safulet/tss-lib-private/schnorr/signing/mina"
	"github.com/Safulet/tss-lib-private/schnorr/signing/zil"
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

	round.temp.Djs[i] = round.temp.pointDi
	round.temp.Ejs[i] = round.temp.pointEi
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
			r2msg := msg.Content().(*SignRound2Message)
			cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
			ok, coordinates := cmtDeCmt.DeCommit(ctx, 4)
			if !ok {
				errChs <- round.WrapError(errors.New("de-commitment verify failed"))
				return
			}
			if len(coordinates) != 4 {
				errChs <- round.WrapError(errors.New("length of de-commitment should be 4"))
				return
			}

			pointDj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
			if err != nil {
				errChs <- round.WrapError(errors.Wrapf(err, "NewECPoint(Dj)"), Pj)
				return
			}
			proofD, err := r2msg.UnmarshalZKProofD(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to unmarshal Dj proof"), Pj)
				return
			}
			ok = proofD.Verify(ctx, ContextJ, pointDj, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to prove Dj"), Pj)
				return
			}
			round.temp.Djs[j] = pointDj

			pointEj, err := crypto.NewECPoint(round.Params().EC(), coordinates[2], coordinates[3])
			if err != nil {
				errChs <- round.WrapError(errors.Wrapf(err, "NewECPoint(Ej)"), Pj)
				return
			}
			proofE, err := r2msg.UnmarshalZKProofE(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to unmarshal Ej proof"), Pj)
				return
			}
			ok = proofE.Verify(ctx, ContextJ, pointEj, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to prove Ej"), Pj)
				return
			}
			round.temp.Ejs[j] = pointEj
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	// compute Rj
	M := new(big.Int).SetBytes(round.temp.m)

	DjFlat, err := crypto.FlattenECPoints(round.temp.Djs)
	if err != nil {
		return round.WrapError(errors.New("failed to flattern Djs"), round.PartyID())
	}
	EjFlat, err := crypto.FlattenECPoints(round.temp.Ejs)
	if err != nil {
		return round.WrapError(errors.New("failed to flattern Ejs"), round.PartyID())
	}

	BIndexes := make([]*big.Int, 0)
	for j := range round.Parties().IDs() {
		BIndexes = append(BIndexes, big.NewInt(int64(j)))
	}
	// <i, Di, Ei>
	DEFlat := append(BIndexes, DjFlat...) // i, Di
	DEFlat = append(DEFlat, EjFlat...)    // i, Ei

	for j, Pj := range round.Parties().IDs() {
		rho := common.SHA512_256i_TAGGED(ctx, []byte(btc.TagNonce), append(DEFlat, M, big.NewInt(int64(j)))...)
		Rj, err := round.temp.Djs[j].Add(round.temp.Ejs[j].ScalarMult(rho))
		if err != nil {
			return round.WrapError(errors.New("error in computing Ri"), Pj)
		}
		round.temp.Rjs[j] = Rj
		round.temp.rhos[j] = rho
	}

	// compute R
	R := round.temp.Rjs[i]
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		var err error
		R, err = R.Add(round.temp.Rjs[j])
		if err != nil {
			return round.WrapError(errors.New("error in computing R"), Pj)
		}
	}

	modQ := common.ModInt(round.EC().Params().N)
	needsNeg := R.Y().Bit(0) != 0
	if needsNeg {
		// Neg R
		YNeg := new(big.Int).Sub(round.EC().Params().P, R.Y())
		R2, err := crypto.NewECPoint(round.EC(), R.X(), YNeg)
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		R = R2

		// Neg Rj
		for j, Pj := range round.Parties().IDs() {
			if j == i {
				continue
			}

			YjNeg := new(big.Int).Sub(round.EC().Params().P, round.temp.Rjs[j].Y())
			Rj2, err := crypto.NewECPoint(round.EC(), round.temp.Rjs[j].X(), YjNeg)
			if err != nil {
				return round.WrapError(err, Pj)
			}
			round.temp.Rjs[j] = Rj2
		}

		// Neg di, ei
		round.temp.di = modQ.Sub(zero, round.temp.di)
		round.temp.ei = modQ.Sub(zero, round.temp.ei)
	}

	// compute child public key
	pkDelta := round.key.PubKey
	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		gDelta := crypto.ScalarBaseMult(round.EC(), round.temp.KeyDerivationDelta)
		var err error
		pkDelta, err = pkDelta.Add(gDelta)
		if err != nil {
			return round.WrapError(errors.New("PubKey derivation failed"), round.PartyID())
		}
	}

	// compute challenge
	var c_ []byte
	switch round.Network() {
	case tss.MINA:
		c_ = mina.SchnorrHash(R.X(), pkDelta, round.temp.m)
	case tss.ZIL:
		c_ = zil.SchnorrHash(zil.GetCompressedBytes(R), zil.GetCompressedBytes(pkDelta), round.temp.m)
	default:
		c_ = common.TaggedHash256([]byte(btc.TagChallenge),
			common.PadToLengthBytesInPlace(R.X().Bytes(), 32),
			common.PadToLengthBytesInPlace(pkDelta.X().Bytes(), 32),
			common.PadToLengthBytesInPlace(round.temp.m, 32))

	}
	c := new(big.Int).Mod(new(big.Int).SetBytes(c_), round.EC().Params().N)
	if c.Cmp(zero) != 1 {
		return round.WrapError(errors.New("challenge computed to be zero"))
	}

	// compute signature share zi
	zi := modQ.Add(round.temp.di, modQ.Mul(round.temp.ei, round.temp.rhos[i]))
	if round.Network() == tss.ZIL {
		zi = modQ.Sub(zi, modQ.Mul(round.temp.wi, c))
	} else {
		zi = modQ.Add(zi, modQ.Mul(round.temp.wi, c))
	}

	round.temp.zi = zi
	round.temp.c = c
	round.temp.R = R
	round.temp.pubKeyDelta = pkDelta
	// broadcast zi to other parties
	r3msg := NewSignRound3Message(round.PartyID(), zi)
	round.temp.signRound3Messages[i] = r3msg
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