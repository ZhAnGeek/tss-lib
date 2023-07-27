// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package derivekey

import (
	"context"
	"errors"
	"fmt"
	zkpeqlog "github.com/Safulet/tss-lib-private/crypto/zkp/eqlog"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"

	h2c "github.com/armfazh/h2c-go-ref"
)

func newRound1(params *tss.Parameters, key *LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- tss.Message) tss.Round {
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

	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.bssid = new(big.Int).SetBytes(ssid[:])

	// ToDo make it general; remove h2c dependency
	dst := "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
	hashToCurve, err := h2c.Secp256k1_XMDSHA256_SSWU_RO_.Get([]byte(dst))
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wpath := append([]byte("DeriveChildKey#SECP256K1#ChainCode#"), round.temp.pChainCode...)

	if tss.SameCurve(tss.Edwards(), round.EC()) {
		dst = "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"
		hashToCurve, err = h2c.Edwards25519_XMDSHA512_ELL2_RO_.Get([]byte(dst))
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		wpath = append([]byte("DeriveChildKey#EDWARDS25519#ChainCode#"), round.temp.pChainCode...)
	}

	wpath = append(wpath, []byte("#Path#")...)
	wpath = append(wpath, round.temp.path...)
	h2cPoint := hashToCurve.Hash(wpath)
	h2cPx := h2cPoint.X().Polynomial()[0]
	h2cPy := h2cPoint.Y().Polynomial()[0]
	pointHi, err := crypto.NewECPoint(round.EC(), h2cPx, h2cPy)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	pointVi := pointHi.ScalarMult(round.temp.wi)
	pointG, err := crypto.NewECPoint(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	proof, err := zkpeqlog.NewProof(ctx, ssid, round.EC(), pointG, pointHi, round.temp.bigWs[i], pointVi, round.temp.wi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	round.temp.pointHi = pointHi
	round.temp.pointVi = pointVi

	// 4. broadcast commitment
	r1msg := NewDeriveKeyRound1Message(round.PartyID(), round.temp.bssid, pointVi.X(), pointVi.Y(), proof)
	round.temp.derivekeyRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.derivekeyRound1Messages {
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
	if _, ok := msg.Content().(*DeriveKeyRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}

// ----- //

// helper to call into PrepareForDeriveKey()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		// TODO: this should not panic
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := PrepareForDeriveKey(round.Params().EC(), i, len(ks), xi, ks, round.key.BigXj)

	round.temp.wi = wi
	round.temp.bigWs = bigWs
	return nil
}
