// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/edwards25519"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"
)

var (
	zero = big.NewInt(0)
)

func (round *finalization) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	_, span := tracer.StartWithFuncSpan(ctx)
	defer span.End()

	round.number = 4
	round.started = true
	round.resetOK()

	modQ := common.ModInt(round.EC().Params().N)
	sumS := round.temp.si
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		sumS = modQ.Add(sumS, r3msg.UnmarshalS())
	}

	// save the signature for final output
	round.data.Signature = append(edwards25519.BigIntToEncodedBytes(round.temp.r)[:],
		edwards25519.BigIntToEncodedBytes(sumS)[:]...)
	round.data.R = round.temp.r.Bytes()
	round.data.S = sumS.Bytes()
	round.data.M = round.temp.m

	pk, err := crypto.NewECPoint(round.EC(), round.temp.PKX, round.temp.PKY)
	if err != nil {
		return round.WrapError(fmt.Errorf("pubkey construction failed"))
	}

	ok := VerifyEdwards(pk, round.temp.m, round.temp.r, sumS, round.HashFunc)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
