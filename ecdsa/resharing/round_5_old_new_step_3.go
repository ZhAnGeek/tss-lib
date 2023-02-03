// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func (round *round5) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()

	Pi := round.PartyID()
	i := Pi.Index

	if round.IsNewCommittee() {
		// Verify ProofFac
		culprits := make([]*tss.PartyID, 0, len(round.NewParties().IDs())) // who caused the error(s)
		ContextI := append(round.temp.SSID, big.NewInt(int64(i)).Bytes()...)
		for j, Pj := range round.NewParties().IDs() {
			if j == i {
				continue
			}

			r4msg1 := round.temp.dgRound4Message1s[j].Content().(*DGRound4Message1)
			proofFac, err := r4msg1.UnmarshalProofFac()
			if err != nil {
				return round.WrapError(errors.New("proofFac failed"), Pj)
			}
			if ok := proofFac.Verify(ctx, ContextI, round.EC(), round.save.NTildej[j],
				round.save.NTildei, round.save.H1i, round.save.H2i); !ok {
				culprits = append(culprits, Pj)
				log.Warn(ctx, "proofFac verify failed for party %s", Pj)
				continue
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("paillier verify failed"), culprits...)
		}

		// 21.
		// for this P: SAVE data
		round.save.BigXj = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.Xi = round.temp.newXi
		round.save.Ks = round.temp.newKs

		// misc: build list of paillier public keys to save
		for j, msg := range round.temp.dgRound2Message1s {
			if j == i {
				continue
			}
			r2msg1 := msg.Content().(*DGRound2Message1)
			round.save.PaillierPKs[j] = r2msg1.UnmarshalPaillierPK()
			if round.save.PaillierPKs[j].N.BitLen() != paillierBitsLen {
				return round.WrapError(errors.New("got Paillier modulus with not enough bits"), msg.GetFrom())
			}
			if round.save.NTildej[j].Cmp(round.save.PaillierPKs[j].N) != 0 {
				return round.WrapError(errors.New("got NTildej not equal to Paillier modulus"), msg.GetFrom())
			}
		}
	} else if round.IsOldCommittee() {
		round.input.Xi.SetInt64(0)
	}

	round.end <- *round.save
	return nil
}

func (round *round5) CanAccept(_ tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
