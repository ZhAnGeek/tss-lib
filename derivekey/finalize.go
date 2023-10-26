// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package derivekey

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *finalization) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	sumZ := round.temp.pointVi
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		round.ok[j] = true
		r1msg := round.temp.derivekeyRound1Messages[j].Content().(*DeriveKeyRound1Message)
		pointVj, err := r1msg.UnmarshalPartialEval(round.EC())
		if err != nil {
			return round.WrapError(errors.New("unmarshal Vj failed"), Pj)
		}

		proof, err := r1msg.UnmarshalProof()
		if err != nil {
			return round.WrapError(errors.New("proof verification failed"), Pj)
		}
		pointG, err := crypto.NewECPoint(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		ok := proof.Verify(ctx, round.temp.bssid.Bytes(), round.EC(), pointG, round.temp.pointHi, round.temp.bigWs[j], pointVj, tss.GetRejectionSampleFunc(round.Version()))
		if !ok {
			return round.WrapError(errors.New("proof verification failed"), Pj)
		}

		sumZ, err = sumZ.Add(pointVj)
	}
	round.data.M = sumZ.X().Bytes()

	hmac512 := hmac.New(sha512.New, round.temp.pChainCode)
	hmac512.Write(sumZ.X().Bytes())
	ilr := hmac512.Sum(nil)
	ilNum := new(big.Int).SetBytes(ilr[:32])
	N := round.EC().Params().N
	qBytesLen := (N.BitLen() >> 3) + 1
	for ilNum.Cmp(N) != -1 {
		ilNumAdd := new(big.Int).Add(ilNum, big.NewInt(1))
		reSampleBytes := sha512.Sum512(append([]byte("ResampleIlNumInDeriveKey"), ilNumAdd.Bytes()...))
		ilNum = new(big.Int).SetBytes(reSampleBytes[:qBytesLen])
	}
	round.temp.cChainCode = ilr[32:]
	log.Debug(ctx, "%s Derived ilNum: 0x%x\nChildChaincode: 0x%x\n",
		round.PartyID(), ilNum, new(big.Int).SetBytes(round.temp.cChainCode))

	result := &DeriveKeyResultMessage{
		Bssid:           round.temp.bssid.Bytes(),
		ParentChainCode: round.temp.pChainCode,
		Index:           round.temp.index,
		Delta:           ilNum.Bytes(),
		ChildChainCode:  round.temp.cChainCode,
	}
	round.end <- result

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
