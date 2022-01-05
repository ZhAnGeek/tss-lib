// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	// Fig 5. Round 2. / Fig 6. Round 2.
	{
		msg := NewKGRound2Message(round.PartyID(), round.temp.vs, &round.save.PaillierSK.PublicKey, round.save.NTildei, round.save.H1i, round.save.H2i, round.temp.Ai, round.temp.rid, round.temp.cmtRandomness, round.temp.proofPrm)
		round.out <- msg
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r2msgVss {
		if round.ok[j] {
			continue
		}
		if msg == nil || round.save.PaillierPKs[j] == nil ||
			round.save.NTildej[j] == nil || round.save.H1j[j] == nil ||
			round.save.H2j[j] == nil || round.temp.r2msgAs[j] == nil ||
			round.temp.r2msgCmtRandomness[j] == nil ||
			round.temp.r2msgRids[j] == nil || round.temp.r2msgpfprm[j] == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
