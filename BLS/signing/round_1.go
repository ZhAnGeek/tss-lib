// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// pairing-based threshold signature is deterministic multiparty signature protocol

package signing

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/BLS/keygen"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/v2/tss"
	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

// round 1 represents round 1 of the signing part of the pairing-based threshold signature spec on BLS12381
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// sign message with private key share

	if round.temp.KeyDerivationDelta != big.NewInt(0) {
		modQ := common.ModInt(round.EC().Params().N)
		round.temp.wi = modQ.Add(round.temp.wi, round.temp.KeyDerivationDelta)
		g2 := bls.NewG2()
		p := g2.Zero()
		g2.MulScalar(p, g2.One(), round.temp.KeyDerivationDelta)
		round.temp.derivePubKey = new(big.Int).SetBytes(g2.ToBytes(p))
	}

	pM := bls12381.Sign(round.temp.wi.Bytes(), round.temp.m)
	round.temp.sig[i] = new(big.Int).SetBytes(pM)

	r1msg := NewSignRound1Message(round.PartyID(), new(big.Int).SetBytes(pM))
	round.temp.signRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		// TODO: this should not panic
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks)

	round.temp.wi = wi
	return nil
}
