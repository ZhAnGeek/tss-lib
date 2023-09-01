// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	zkpfac "github.com/Safulet/tss-lib-private/crypto/zkp/fac"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round3) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()
	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 1. create proof enc
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	Pi := round.PartyID()
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg := sync.WaitGroup{}
		contextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			proofPrm := round.temp.ProofPrms[j]
			if ok := proofPrm.Verify(ctx, contextJ, round.save.H1j[j], round.save.H2j[j], round.save.NTildej[j]); !ok {
				errChs <- round.WrapError(fmt.Errorf("ProofMod failed"), Pj)
			}
			proofMod := round.temp.ProofMods[j]
			if ok := proofMod.Verify(ctx, contextJ, round.save.NTildej[j], rejectionSample); !ok {
				errChs <- round.WrapError(fmt.Errorf("ProofMod failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			SP := new(big.Int).Add(new(big.Int).Lsh(round.save.LocalPreParams.P, 1), big.NewInt(1))
			SQ := new(big.Int).Add(new(big.Int).Lsh(round.save.LocalPreParams.Q, 1), big.NewInt(1))
			proofFac, err := zkpfac.NewProof(ctx, contextJ, round.EC(), round.save.LocalPreParams.PaillierSK.N,
				round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j], SP, SQ, rejectionSample)

			if err != nil {
				errChs <- round.WrapError(errors.New("create proofMod failed"), Pi)
			}
			r3msg1 := NewKGRound3Message1(Pj, round.PartyID(), proofFac)
			round.out <- r3msg1
		}(j, Pj)

		wg.Wait()
	}
	close(errChs)
	for err := range errChs {
		return err
	}

	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j := range round.temp.ProofFacs {
		if round.ok[j] {
			continue
		}
		if round.temp.ProofFacs[j] == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	fmt.Println("all received", round.PartyID().Index)
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &roundout{round}
}
