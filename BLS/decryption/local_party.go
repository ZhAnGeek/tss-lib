// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/BLS/keygen"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type DecryptedData DecryptionFinalMessage

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		key  keygen.LocalPartySaveData
		temp localTempData
		data DecryptedData

		// outbound messaging
		out chan<- tss.Message
		end chan<- DecryptedData
	}

	localMessageStore struct {
		decryptionRound1Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		suite         []byte
		PublicKeySize int
		SignatureSize int

		wi           *big.Int
		derivePubKey *big.Int

		m      []byte
		shares []*big.Int
		// public key (Xj = uj*G for each Pj)
		wj []*crypto.ECPoint // Xj
	}
)

func NewLocalParty(
	ctx context.Context,
	msg []byte,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- DecryptedData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		key:       keygen.BuildLocalSaveDataSubset(ctx, key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      DecryptedData{},
		out:       out,
		end:       end,
	}
	// temp data init
	p.temp.decryptionRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.m = msg
	p.temp.shares = make([]*big.Int, partyCount)

	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.key, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start(ctx context.Context) *tss.Error {
	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	return tss.BaseStart(ctx, p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(ctx context.Context, msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(ctx, p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(ctx context.Context, wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(ctx, msg)
}

func (p *LocalParty) StoreMessage(ctx context.Context, msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *DecryptionRound1Message:
		p.temp.decryptionRound1Messages[fromPIdx] = msg
		p.temp.shares[fromPIdx] = new(big.Int).SetBytes(msg.Content().(*DecryptionRound1Message).CipherText)

	default: // unrecognised message, just ignore!
		log.Warn(ctx, "unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
