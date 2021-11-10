// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	zkpsch "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"
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
		end chan<- LocalPartySaveData
	}

	//localMessageStore struct {
	//	kgRound1Messages,
	//	kgRound2Message1s,
	//	kgRound2Message2s,
	//	kgRound3Messages []tss.ParsedMessage
	//}

	localTempData struct {
		//localMessageStore

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		KGCs          []cmt.HashCommitment
		vs            vss.Vs
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment

		//
		r2msg1Shares   []*big.Int
		r2msg2Decommit []cmt.HashDeCommitment
		r2msg2Proof    []*zkpsch.ProofSch
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
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
	//p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	//p.temp.kgRound2Message1s = make([]tss.ParsedMessage, partyCount)
	//p.temp.kgRound2Message2s = make([]tss.ParsedMessage, partyCount)
	//p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)

	p.temp.r2msg1Shares = make([]*big.Int, partyCount)
	p.temp.r2msg2Decommit = make([][]*big.Int, partyCount)
	p.temp.r2msg2Proof = make([]*zkpsch.ProofSch, partyCount)
	// temp data init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
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
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *KGRound1Message:
		//p.temp.kgRound1Messages[fromPIdx] = msg
		r1msg := msg.Content().(*KGRound1Message)
		p.temp.KGCs[fromPIdx] = r1msg.UnmarshalCommitment()
	case *KGRound2Message1:
		//p.temp.kgRound2Message1s[fromPIdx] = msg
		r2msg1 := msg.Content().(*KGRound2Message1)
		p.temp.r2msg1Shares[fromPIdx] = r2msg1.UnmarshalShare()
	case *KGRound2Message2:
		//p.temp.kgRound2Message2s[fromPIdx] = msg
		r2msg2 := msg.Content().(*KGRound2Message2)
		p.temp.r2msg2Decommit[fromPIdx] = r2msg2.UnmarshalDeCommitment()
		proof, err := r2msg2.UnmarshalZKProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg2Proof[fromPIdx] = proof
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
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