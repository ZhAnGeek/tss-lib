// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package shared_secret

import (
	"context"
	"errors"
	"fmt"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	zkpeqlog "github.com/Safulet/tss-lib-private/v2/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *crypto.ECPoint) tss.Round {
	return &round1{&base{params, key, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Pi := round.PartyID()
	round.ok[i] = true

	AiB := round.temp.B.ScalarMult(round.temp.W)
	if AiB == nil {
		return round.WrapError(fmt.Errorf("failed to compute a_i * B"), Pi)
	}
	round.temp.AiB[i] = AiB
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.Ssid = ssid
	g, _ := crypto.NewECPoint(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	proof, err := zkpeqlog.NewProof(ctx, ssid, round.EC(), g, round.temp.B, round.temp.BigWs[i], AiB, round.temp.W, common.RejectionSampleV2)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.EqProofs[i] = proof

	r1msg := NewSharedSecretRound1Message(round.PartyID(), AiB, proof)
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.AiB {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SharedSecretRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

func (round *round1) prepare() error {
	i := round.PartyID().Index

	modN := common.ModInt(round.EC().Params().N)
	xi := modN.Add(round.key.Xi, round.temp.KeyDerivationDelta)
	ks := round.key.Ks
	BigXs := round.key.BigXj
	gDelta := crypto.ScalarBaseMult(round.EC(), round.temp.KeyDerivationDelta)
	var err error
	for idx := range BigXs {
		BigXs[idx], err = BigXs[idx].Add(gDelta)
		if err != nil {
			return err
		}
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, BigWs := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs)

	round.temp.W = wi
	round.temp.BigWs = BigWs

	return nil
}
