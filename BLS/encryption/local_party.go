// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package encryption

import (
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/BLS/keygen"
	"github.com/Safulet/tss-lib-private/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters
		temp   localTempData

		key keygen.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- EncryptedData
	}

	localTempData struct {
		// localMessageStore
		m *big.Int
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- EncryptedData,
) tss.Party {
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		key:       keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{m: msg},
		out:       out,
		end:       end,
	}
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.key, &p.temp, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
