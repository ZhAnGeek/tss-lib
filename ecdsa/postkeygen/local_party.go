// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	zkpfac "github.com/Safulet/tss-lib-private/crypto/zkp/fac"
	zkpmod "github.com/Safulet/tss-lib-private/crypto/zkp/mod"
	zkpprm "github.com/Safulet/tss-lib-private/crypto/zkp/prm"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

const (
	paillierBitsLen = 2048
)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data keygen.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *keygen.LocalPartySaveData
	}

	localTempData struct {
		// temp data (thrown away after keygen)
		ssid      []byte
		ssidNonce *big.Int

		// for ui
		Acks      []bool
		ProofPrms []*zkpprm.ProofPrm
		ProofMods []*zkpmod.ProofMod
		ProofFacs []*zkpfac.ProofFac
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- *keygen.LocalPartySaveData,
	optionalPreParams ...keygen.LocalPreParams,
) tss.Party {
	partyCount := params.PartyCount()
	data := keygen.NewLocalPartySaveData(partyCount)
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

	p.temp.ProofFacs = make([]*zkpfac.ProofFac, partyCount)
	p.temp.ProofPrms = make([]*zkpprm.ProofPrm, partyCount)
	p.temp.ProofMods = make([]*zkpmod.ProofMod, partyCount)
	p.temp.Acks = make([]bool, partyCount)

	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRoundStart(p.params, &p.data, &p.temp, p.out, p.end)
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

func (p *LocalParty) StoreMessage(ctx context.Context, msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}

	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *KGRound1MessageAck:
		p.temp.Acks[fromPIdx] = true
	case *KGRound2Message1:
		r2msg := msg.Content().(*KGRound2Message1)
		// commitment for schnorr scheme
		var err error
		p.temp.ProofPrms[fromPIdx], err = r2msg.UnmarshalProofPrm()
		if err != nil {
			return false, p.WrapError(errors.New("invalid proof prm"), msg.GetFrom())
		}
		p.temp.ProofMods[fromPIdx], err = r2msg.UnmarshalProofMod()
		if err != nil {
			return false, p.WrapError(errors.New("invalid proof mod"), msg.GetFrom())
		}

		p.data.H1j[fromPIdx] = r2msg.UnmarshalH1()
		p.data.H2j[fromPIdx] = r2msg.UnmarshalH2()
		p.data.PaillierPKs[fromPIdx] = r2msg.UnmarshalPaillierPK() // used in round 4
		if p.data.PaillierPKs[fromPIdx].N.BitLen() != paillierBitsLen {
			return false, p.WrapError(errors.New("got Paillier modulus with not enough bits"), msg.GetFrom())
		}
		p.data.NTildej[fromPIdx] = r2msg.UnmarshalNTilde()
		if p.data.NTildej[fromPIdx].Cmp(p.data.PaillierPKs[fromPIdx].N) != 0 {
			return false, p.WrapError(errors.New("got NTildej not equal to Paillier modulus"), msg.GetFrom())
		}
	case *KGRound3Message1:
		r3msg1 := msg.Content().(*KGRound3Message1)
		facProof, err := r3msg1.UnmarshalFacProof()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.ProofFacs[fromPIdx] = facProof
	default: // unrecognised message, just ignore!
		log.Warn(ctx, "unrecognised message ignored: %v", msg)
		return true, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
