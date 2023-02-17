// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round5) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()
	i := round.PartyID().Index

	if round.IsNewCommittee() {
		// for this P: SAVE data
		round.save.BigXj = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.Xi = round.temp.newXi
		round.save.Ks = round.temp.newKs

		// for other P: save Paillier
		for j, message := range round.temp.dgRound1MessagesNewParty {
			if message == nil {
				continue
			}
			if j == i {
				continue
			}
			dgMessage := message.Content().(*DGRound1MessageNewParty)
			round.save.PaillierPKs[j] = dgMessage.UnmarshalPaillierPK()
			round.save.H1j[j] = dgMessage.UnmarshalH1()
			round.save.H2j[j] = dgMessage.UnmarshalH2()
			round.save.NTildej[j] = dgMessage.UnmarshalNTilde()
		}

	} else if round.IsOldCommittee() {
		round.input.Xi.SetInt64(0)
	}

	round.end <- *round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
