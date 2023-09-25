// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	cmt "github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/schnorr/keygen"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.SignatureData
	}

	localMessageStore struct {
		signRound1Messages,
		signRound2Messages,
		signRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		ssid               []byte
		ssidNonce          *big.Int
		wi                 *big.Int
		bigWs              []*crypto.ECPoint
		di                 *big.Int
		ei                 *big.Int
		m                  []byte
		KeyDerivationDelta *big.Int
		pubKeyDelta        *crypto.ECPoint // derived child public key
		pointDi            *crypto.ECPoint
		pointEi            *crypto.ECPoint
		deCommit           cmt.HashDeCommitment

		// round 2
		cjs  []*big.Int
		zi   *big.Int
		Djs  []*crypto.ECPoint
		Ejs  []*crypto.ECPoint
		Rjs  []*crypto.ECPoint
		rhos []*big.Int
		c    *big.Int
		R    *crypto.ECPoint

		// round 3
	}
)

func NewLocalParty(
	msg []byte,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.KeyDerivationDelta = keyDerivationDelta
	p.temp.m = msg
	p.temp.cjs = make([]*big.Int, partyCount)

	p.temp.Djs = make([]*crypto.ECPoint, partyCount)
	p.temp.Ejs = make([]*crypto.ECPoint, partyCount)
	p.temp.Rjs = make([]*crypto.ECPoint, partyCount)
	p.temp.rhos = make([]*big.Int, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
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
	case *SignRound1Message:
		p.temp.signRound1Messages[fromPIdx] = msg

	case *SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg

	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg

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