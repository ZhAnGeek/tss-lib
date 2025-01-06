// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keyshare_affine_transform

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
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
		A, B *big.Int
		key  keygen.LocalPartySaveData
		data keygen.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *keygen.LocalPartySaveData
	}

	localTempData struct {
		ssid               []byte
		W                  *big.Int
		BigWs              []*crypto.ECPoint
		A                  *big.Int
		B                  *big.Int
		KeyDerivationDelta *big.Int

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		shares        vss.Shares
		vs            vss.Vs
		alphai        *big.Int // pfsch randomness
		Ai            *crypto.ECPoint
		rid           *big.Int
		cmtRandomness *big.Int
		RidAllBz      []byte

		r1msgVHashs        []*big.Int
		r2msgVss           [][]*crypto.ECPoint
		r2msgAs            []*crypto.ECPoint
		r2msgRids          []*big.Int
		r2msgCmtRandomness []*big.Int
		r2msgxij           []*big.Int
		r3msgpfsch         []*zkpsch.ProofSch
	}
)

const (
	SafeBitsLen = 2048
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	A, B *big.Int,
	out chan<- tss.Message,
	end chan<- *keygen.LocalPartySaveData,
) tss.Party {
	partyCount := params.PartyCount()
	data := keygen.NewLocalPartySaveData(partyCount)
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		key:       keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs data init
	p.temp.A = A
	p.temp.B = B
	p.temp.KeyDerivationDelta = keyDerivationDelta
	p.temp.BigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.r1msgVHashs = make([]*big.Int, partyCount)
	p.temp.r2msgVss = make([][]*crypto.ECPoint, partyCount)
	p.temp.r2msgAs = make([]*crypto.ECPoint, partyCount)
	p.temp.r2msgRids = make([]*big.Int, partyCount)
	p.temp.r2msgCmtRandomness = make([]*big.Int, partyCount)
	p.temp.r2msgxij = make([]*big.Int, partyCount)
	p.temp.r3msgpfsch = make([]*zkpsch.ProofSch, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.key, &p.data, &p.temp, p.out, p.end)
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
	return tss.BaseUpdatePool(ctx, p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(ctx context.Context, wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(ctx, msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d < %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
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
	case *KTRound1Message:
		r1msg := msg.Content().(*KTRound1Message)
		p.temp.r1msgVHashs[fromPIdx] = r1msg.UnmarshalVHash()
	case *KTRound2Message1:
		r2msg := msg.Content().(*KTRound2Message1)
		var err error
		p.temp.r2msgVss[fromPIdx], err = r2msg.UnmarshalVs(p.params.EC())
		if err != nil {
			return false, p.WrapError(err)
		}
		p.temp.r2msgAs[fromPIdx], err = r2msg.UnmarshalA(p.params.EC())
		if err != nil {
			return false, p.WrapError(err)
		}
		p.temp.r2msgRids[fromPIdx] = r2msg.UnmarshalRid()
		p.temp.r2msgCmtRandomness[fromPIdx] = r2msg.UnmarshalCmtRandomness()
	case *KTRound2Message2:
		r2msg2 := msg.Content().(*KTRound2Message2)
		xij, err := p.key.PaillierSK.Decrypt(r2msg2.UnmarshalShare())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r2msgxij[fromPIdx] = xij
	case *KTRound3Message:
		r3msg := msg.Content().(*KTRound3Message)
		proof, err := r3msg.UnmarshalProofSch(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgpfsch[fromPIdx] = proof

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
