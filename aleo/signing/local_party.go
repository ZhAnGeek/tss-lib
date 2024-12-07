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

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	cmt "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

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

		// outbound messaging
		out chan<- tss.Message
		end chan<- *RequestOut
	}

	localMessageStore struct {
		signRound1Messages,
		signRound2Messages,
		signRound3Messages,
		signRound4Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		childAddr  *crypto.ECPoint
		childPkSig *crypto.ECPoint
		childPrSig *crypto.ECPoint
		signInputs RInputs
		pointUs    []*crypto.ECPoint // for B = r * U
		ssid       []byte
		ssidNonce  *big.Int
		w1i        *big.Int
		bigW1s     []*crypto.ECPoint
		w2i        *big.Int
		bigW2s     []*crypto.ECPoint
		di         *big.Int
		ei         *big.Int
		m          []byte
		pointDi    *crypto.ECPoint
		pointEi    *crypto.ECPoint
		deCommit   cmt.HashDeCommitment

		// round 2
		pointH1 *crypto.ECPoint
		pointH2 *crypto.ECPoint
		pointV1 *crypto.ECPoint
		pointV2 *crypto.ECPoint
		cjs     []*big.Int
		ri      *big.Int
		Djs     []*crypto.ECPoint
		Ejs     []*crypto.ECPoint
		Rjs     []*crypto.ECPoint
		rhos    []*big.Int
		R       *crypto.ECPoint
		skTag   *big.Int

		// round 3
		tvkShare *crypto.ECPoint
		bShare   *crypto.ECPoint
		tvk      *crypto.ECPoint
		Bs       []*crypto.ECPoint
		gammas   []*crypto.ECPoint
		// gammaShares []*crypto.ECPoint
		challenge     *big.Int
		tcm           *big.Int
		scm           *big.Int
		responseShare *big.Int

		PkSigDelta *big.Int
		PrSigDelta *big.Int
	}
)

func NewLocalParty(
	nonce *big.Int,
	pointUs []*crypto.ECPoint,
	signInputs RInputs,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	PkSigDerivationDelta *big.Int,
	PrSigDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- *RequestOut,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.signInputs = signInputs
	p.temp.pointUs = pointUs
	p.temp.bigW1s = make([]*crypto.ECPoint, partyCount)
	p.temp.bigW2s = make([]*crypto.ECPoint, partyCount)
	p.temp.ssidNonce = nonce
	p.temp.cjs = make([]*big.Int, partyCount)
	p.temp.Bs = make([]*crypto.ECPoint, len(pointUs))
	p.temp.gammas = make([]*crypto.ECPoint, len(pointUs))

	p.temp.Djs = make([]*crypto.ECPoint, partyCount)
	p.temp.Ejs = make([]*crypto.ECPoint, partyCount)
	p.temp.Rjs = make([]*crypto.ECPoint, partyCount)
	p.temp.rhos = make([]*big.Int, partyCount)
	p.temp.PkSigDelta = PkSigDerivationDelta
	p.temp.PrSigDelta = PrSigDerivationDelta
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.temp, p.out, p.end)
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

	case *SignRound4Message:
		p.temp.signRound4Messages[fromPIdx] = msg

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
