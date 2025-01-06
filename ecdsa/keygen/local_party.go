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

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpfac "github.com/Safulet/tss-lib-private/v2/crypto/zkp/fac"
	zkpmod "github.com/Safulet/tss-lib-private/v2/crypto/zkp/mod"
	zkpprm "github.com/Safulet/tss-lib-private/v2/crypto/zkp/prm"
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
		ssid []byte
		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		shares        vss.Shares
		vs            vss.Vs
		alphai        *big.Int // pfsch randomness
		Ai            *crypto.ECPoint
		rid           *big.Int
		cmtRandomness *big.Int
		proofPrm      *zkpprm.ProofPrm
		RidAllBz      []byte

		r1msgVHashs        []*big.Int
		r2msgVss           [][]*crypto.ECPoint
		r2msgAs            []*crypto.ECPoint
		r2msgRids          []*big.Int
		r2msgCmtRandomness []*big.Int
		r2msgpfprm         []*zkpprm.ProofPrm
		r3msgxij           []*big.Int
		r3msgpfmod         []*zkpmod.ProofMod
		r3msgpffac         []*zkpfac.ProofFac
		r4msgpfsch         []*zkpsch.ProofSch
	}
)

const (
	paillierBitsLen = 2048
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
	optionalPreParams ...LocalPreParams,
) tss.Party {
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	// when `optionalPreParams` is provided we'll use the pre-computed primes instead of generating them from scratch
	if 0 < len(optionalPreParams) {
		if 1 < len(optionalPreParams) {
			panic(errors.New("keygen.NewLocalParty expected 0 or 1 item in `optionalPreParams`"))
		}
		if !optionalPreParams[0].Validate() {
			panic(errors.New("keygen.NewLocalParty: `optionalPreParams` failed to validate"))
		}
		data.LocalPreParams = optionalPreParams[0]
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs data init
	p.temp.r1msgVHashs = make([]*big.Int, partyCount)
	p.temp.r2msgVss = make([][]*crypto.ECPoint, partyCount)
	p.temp.r2msgAs = make([]*crypto.ECPoint, partyCount)
	p.temp.r2msgRids = make([]*big.Int, partyCount)
	p.temp.r2msgCmtRandomness = make([]*big.Int, partyCount)
	p.temp.r2msgpfprm = make([]*zkpprm.ProofPrm, partyCount)
	p.temp.r3msgxij = make([]*big.Int, partyCount)
	p.temp.r3msgpfmod = make([]*zkpmod.ProofMod, partyCount)
	p.temp.r3msgpffac = make([]*zkpfac.ProofFac, partyCount)
	p.temp.r4msgpfsch = make([]*zkpsch.ProofSch, partyCount)
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
	case *KGRound1Message:
		r1msg := msg.Content().(*KGRound1Message)
		p.temp.r1msgVHashs[fromPIdx] = r1msg.UnmarshalVHash()
	case *KGRound2Message:
		r2msg := msg.Content().(*KGRound2Message)
		p.data.PaillierPKs[fromPIdx] = r2msg.UnmarshalPaillierPK() // used in round 4
		if p.data.PaillierPKs[fromPIdx].N.BitLen() != paillierBitsLen {
			return false, p.WrapError(errors.New("got Paillier modulus with not enough bits"), msg.GetFrom())
		}
		p.data.NTildej[fromPIdx] = r2msg.UnmarshalNTilde()
		if p.data.NTildej[fromPIdx].Cmp(p.data.PaillierPKs[fromPIdx].N) != 0 {
			return false, p.WrapError(errors.New("got NTildej not equal to Paillier modulus"), msg.GetFrom())
		}
		p.data.H1j[fromPIdx], p.data.H2j[fromPIdx] = r2msg.UnmarshalH1(), r2msg.UnmarshalH2()
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
		proofPrm, err := r2msg.UnmarshalProofPrm()
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r2msgpfprm[fromPIdx] = proofPrm
	case *KGRound3Message:
		r3msg := msg.Content().(*KGRound3Message)
		xij, err := p.data.PaillierSK.Decrypt(r3msg.UnmarshalShare())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgxij[fromPIdx] = xij
		proofMod, err := r3msg.UnmarshalProofMod()
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgpfmod[fromPIdx] = proofMod

		proofFac, err := r3msg.UnmarshalProofFac()
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r3msgpffac[fromPIdx] = proofFac

	case *KGRound4Message:
		r4msg := msg.Content().(*KGRound4Message)
		proof, err := r4msg.UnmarshalProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, p.params.Parties().IDs()[fromPIdx])
		}
		p.temp.r4msgpfsch[fromPIdx] = proof

	default: // unrecognised message, just ignore!
		log.Warn(ctx, "unrecognised message ignored: %v", msg)
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
