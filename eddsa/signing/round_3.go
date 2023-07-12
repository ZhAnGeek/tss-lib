// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round3) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	// 1. init R
	var R edwards25519.ExtendedGroupElement
	riBytes := bigIntToEncodedBytes(round.temp.ri)
	edwards25519.GeScalarMultBase(&R, riBytes)

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
		ok = proof.Verify(ctx, ContextJ, Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		extendedRj := ecPointToExtendedElement(round.Params().EC(), Rj.X(), Rj.Y())
		R = addExtendedElements(R, extendedRj)
	}

	// Compute PubKey with Delta
	PKwDelta := ecPointToExtendedElement(round.EC(), round.key.EDDSAPub.X(), round.key.EDDSAPub.Y())
	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		var gDelta edwards25519.ExtendedGroupElement
		kdBytes := bigIntToEncodedBytes(round.temp.KeyDerivationDelta)
		edwards25519.GeScalarMultBase(&gDelta, kdBytes)
		PKwDelta = addExtendedElements(PKwDelta, gDelta)
	}
	var recip, pkx, pky edwards25519.FieldElement
	var xBz, yBz [32]byte
	edwards25519.FeInvert(&recip, &PKwDelta.Z)
	edwards25519.FeMul(&pkx, &PKwDelta.X, &recip)
	edwards25519.FeMul(&pky, &PKwDelta.Y, &recip)
	edwards25519.FeToBytes(&xBz, &pkx)
	edwards25519.FeToBytes(&yBz, &pky)
	round.temp.PKX = encodedBytesToBigInt(&xBz)
	round.temp.PKY = encodedBytesToBigInt(&yBz)

	// 7. compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)
	encodedPubKey := ecPointToEncodedBytes(round.temp.PKX, round.temp.PKY)

	// h = hash512(k || A || M)
	h := round.Parameters.HashFunc()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	h.Write(round.temp.m)

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// 8. compute si
	var localS [32]byte
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(round.temp.wi), riBytes)

	// 9. store r3 message pieces
	round.temp.si = &localS
	round.temp.r = encodedBytesToBigInt(&encodedR)

	// 10. broadcast si to other parties
	r3msg := NewSignRound3Message(round.PartyID(), encodedBytesToBigInt(&localS))
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
