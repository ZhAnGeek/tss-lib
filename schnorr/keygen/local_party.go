// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"

	"github.com/Safulet/tss-lib-private/frost/keygen"
	"github.com/Safulet/tss-lib-private/tss"
)

const (
	TaskName = "schnorr-keygen"
)

type LocalParty struct {
	*keygen.LocalParty
	frostEnd chan keygen.LocalPartySaveData
	end      chan<- LocalPartySaveData
}

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
) tss.Party {
	frostEnd := make(chan keygen.LocalPartySaveData, params.PartyCount())
	params.SetIsSchnorr()
	return &LocalParty{
		keygen.NewLocalParty(params, out, frostEnd).(*keygen.LocalParty),
		frostEnd,
		end,
	}
}

func (p *LocalParty) Start(ctx context.Context) *tss.Error {
	go func() {
		select {
		case save := <-p.frostEnd:
			p.end <- LocalPartySaveData{
				save,
			}
		}
	}()
	return p.LocalParty.Start(ctx)
}
