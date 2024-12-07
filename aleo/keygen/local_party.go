// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	cmt "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
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

		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *LocalPartySaveData
	}

	localTempData struct {
		// temp data (thrown away after keygen)
		ssid           []byte
		ssidNonce      *big.Int
		KGCs1          []cmt.HashCommitment
		u1i            *big.Int
		vs1            vss.Vs
		shares1        vss.Shares
		deCommitPolyG1 cmt.HashDeCommitment
		KGCs2          []cmt.HashCommitment
		u2i            *big.Int
		vs2            vss.Vs
		shares2        vss.Shares
		deCommitPolyG2 cmt.HashDeCommitment

		//
		r2msg1SigShares   []*big.Int
		r2msg2SigDecommit []cmt.HashDeCommitment
		r2msg2SigProof    []*zkpsch.ProofSch
		r2msg1RShares     []*big.Int
		r2msg2RDecommit   []cmt.HashDeCommitment
		r2msg2RProof      []*zkpsch.ProofSch
	}
)

// NewLocalParty Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
) tss.Party {
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.r2msg1SigShares = make([]*big.Int, partyCount)
	p.temp.r2msg2SigDecommit = make([][]*big.Int, partyCount)
	p.temp.r2msg2SigProof = make([]*zkpsch.ProofSch, partyCount)
	p.temp.r2msg1RShares = make([]*big.Int, partyCount)
	p.temp.r2msg2RDecommit = make([][]*big.Int, partyCount)
	p.temp.r2msg2RProof = make([]*zkpsch.ProofSch, partyCount)
	// temp data init
	p.temp.KGCs1 = make([]cmt.HashCommitment, partyCount)
	p.temp.KGCs2 = make([]cmt.HashCommitment, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start(ctx context.Context) *tss.Error {
	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	return tss.BaseStart(ctx, p, TaskName)
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
	case *KGRound1Message:
		r1msg := msg.Content().(*KGRound1Message)
		p.temp.KGCs1[fromPIdx] = r1msg.UnmarshalSigCommitment()
		p.temp.KGCs2[fromPIdx] = r1msg.UnmarshalRCommitment()
	case *KGRound2Message1:
		r2msg1 := msg.Content().(*KGRound2Message1)
		p.temp.r2msg1SigShares[fromPIdx] = r2msg1.UnmarshalSigShare()
		p.temp.r2msg1RShares[fromPIdx] = r2msg1.UnmarshalRShare()
	case *KGRound2Message2:
		r2msg2 := msg.Content().(*KGRound2Message2)
		p.temp.r2msg2SigDecommit[fromPIdx] = r2msg2.UnmarshalSigDeCommitment()
		proof, err := r2msg2.UnmarshalSigZKProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg2SigProof[fromPIdx] = proof
		p.temp.r2msg2RDecommit[fromPIdx] = r2msg2.UnmarshalRDeCommitment()
		proof, err = r2msg2.UnmarshalRZKProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg2RProof[fromPIdx] = proof
	default: // unrecognised message, just ignore!
		log.Warn(ctx, "unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// OriginalIndex recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
