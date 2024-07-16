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
	cmt "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpaffg "github.com/Safulet/tss-lib-private/v2/crypto/zkp/affg"
	zkpenc "github.com/Safulet/tss-lib-private/v2/crypto/zkp/enc"
	zkpfac "github.com/Safulet/tss-lib-private/v2/crypto/zkp/fac"
	zkplogstar "github.com/Safulet/tss-lib-private/v2/crypto/zkp/logstar"
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

const (
	paillierBitsLen = 2048
)

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
		ssid      []byte
		ssidNonce *big.Int
		ui        *big.Int // used for tests
		ri        *big.Int
		xi        *big.Int

		// for ui
		KGCs          []cmt.HashCommitment
		ProofPrms     []*zkpprm.ProofPrm
		ProofMods     []*zkpmod.ProofMod
		vs            vss.Vs
		vsXshares     vss.Shares
		deCommitPolyG cmt.HashDeCommitment

		// for ri
		rKGCs          []cmt.HashCommitment
		rvs            vss.Vs
		vsRshares      vss.Shares
		rdeCommitPolyG cmt.HashDeCommitment

		RNonce *big.Int
		R      *big.Int
		RShare *big.Int

		XNonce *big.Int
		X      *big.Int
		XShare *big.Int

		r1msg1R        []*big.Int
		r1msg1X        []*big.Int
		r2msg1FacProof []*zkpfac.ProofFac
		r2msg1Proof    []*zkpenc.ProofEnc

		// for X
		r2msg1SharesX   []*big.Int
		r2msg2DecommitX []cmt.HashDeCommitment
		r2msg2ProofX    []*zkpsch.ProofSch

		// for R
		r2msg1SharesR   []*big.Int
		r2msg2DecommitR []cmt.HashDeCommitment
		r2msg2ProofR    []*zkpsch.ProofSch

		RXShareBetas  []*big.Int
		RXShareAlphas []*big.Int
		BigXShare     *crypto.ECPoint
		BigXAll       *crypto.ECPoint

		RXMtAFs       []*big.Int
		RXMtADs       []*big.Int
		RXMtARXProofs []*zkpaffg.ProofAffg

		r3msgBigXShare    []*crypto.ECPoint
		r3msgRXD          []*big.Int
		r3msgRXF          []*big.Int
		r3msgRXProof      []*zkpaffg.ProofAffg
		r3msgProofLogstar []*zkplogstar.ProofLogstar

		r4msgRXShare       []*big.Int
		r4msgBigRXShare    []*crypto.ECPoint
		r4msgProofLogstars []*zkplogstar.ProofLogstar
		BigRXShare         *crypto.ECPoint
		RXShare            *big.Int
	}
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

	p.temp.r1msg1X = make([]*big.Int, partyCount)
	p.temp.r1msg1R = make([]*big.Int, partyCount)
	p.temp.r2msg1FacProof = make([]*zkpfac.ProofFac, partyCount)
	p.temp.r2msg1Proof = make([]*zkpenc.ProofEnc, partyCount)

	// msgs init for X
	p.temp.r2msg1SharesX = make([]*big.Int, partyCount)
	p.temp.r2msg2DecommitX = make([][]*big.Int, partyCount)
	p.temp.r2msg2ProofX = make([]*zkpsch.ProofSch, partyCount)

	// msgs init for R
	p.temp.r2msg1SharesR = make([]*big.Int, partyCount)
	p.temp.r2msg2DecommitR = make([][]*big.Int, partyCount)
	p.temp.r2msg2ProofR = make([]*zkpsch.ProofSch, partyCount)

	// ----- //
	p.temp.RXShareBetas = make([]*big.Int, partyCount)
	p.temp.RXShareAlphas = make([]*big.Int, partyCount)

	p.temp.RXMtAFs = make([]*big.Int, partyCount)
	p.temp.RXMtADs = make([]*big.Int, partyCount)
	p.temp.RXMtARXProofs = make([]*zkpaffg.ProofAffg, partyCount)

	p.temp.r3msgBigXShare = make([]*crypto.ECPoint, partyCount)
	p.temp.r3msgRXD = make([]*big.Int, partyCount)
	p.temp.r3msgRXF = make([]*big.Int, partyCount)
	p.temp.r3msgRXProof = make([]*zkpaffg.ProofAffg, partyCount)
	p.temp.r3msgProofLogstar = make([]*zkplogstar.ProofLogstar, partyCount)

	p.temp.r4msgRXShare = make([]*big.Int, partyCount)
	p.temp.r4msgBigRXShare = make([]*crypto.ECPoint, partyCount)
	p.temp.r4msgProofLogstars = make([]*zkplogstar.ProofLogstar, partyCount)

	// temp data init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	p.temp.rKGCs = make([]cmt.HashCommitment, partyCount)
	p.temp.ProofPrms = make([]*zkpprm.ProofPrm, partyCount)
	p.temp.ProofMods = make([]*zkpmod.ProofMod, partyCount)

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
	case *KGRound1Message1:
		r1msg := msg.Content().(*KGRound1Message1)
		// commitment for schnorr scheme
		p.temp.KGCs[fromPIdx] = r1msg.UnmarshalXCommitment()
		p.temp.rKGCs[fromPIdx] = r1msg.UnmarshalRCommitment()

		var err error
		p.temp.ProofPrms[fromPIdx], err = r1msg.UnmarshalProofPrm()
		if err != nil {
			return false, p.WrapError(errors.New("invalid proof prm"), msg.GetFrom())
		}
		p.temp.ProofMods[fromPIdx], err = r1msg.UnmarshalProofMod()
		if err != nil {
			return false, p.WrapError(errors.New("invalid proof mod"), msg.GetFrom())
		}

		// r1msgs R for mta
		p.temp.r1msg1R[fromPIdx] = r1msg.UnmarshalR()

		// r1msgs X for mta
		p.temp.r1msg1X[fromPIdx] = r1msg.UnmarshalX()

		// r1msgs for mta Paillier
		p.data.H1j[fromPIdx] = r1msg.UnmarshalH1()
		p.data.H2j[fromPIdx] = r1msg.UnmarshalH2()
		p.data.PaillierPKs[fromPIdx] = r1msg.UnmarshalPaillierPK() // used in round 4
		if p.data.PaillierPKs[fromPIdx].N.BitLen() != paillierBitsLen {
			return false, p.WrapError(errors.New("got Paillier modulus with not enough bits"), msg.GetFrom())
		}
		p.data.NTildej[fromPIdx] = r1msg.UnmarshalNTilde()
		if p.data.NTildej[fromPIdx].Cmp(p.data.PaillierPKs[fromPIdx].N) != 0 {
			return false, p.WrapError(errors.New("got NTildej not equal to Paillier modulus"), msg.GetFrom())
		}
	case *KGRound2Message1:
		// p.temp.kgRound2Message1s[fromPIdx] = msg
		r2msg1 := msg.Content().(*KGRound2Message1)
		p.temp.r2msg1SharesX[fromPIdx] = r2msg1.UnmarshalXShare()
		p.temp.r2msg1SharesR[fromPIdx] = r2msg1.UnmarshalRShare()
		Proof, err := r2msg1.UnmarshalEncProof()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg1Proof[fromPIdx] = Proof
		facProof, err := r2msg1.UnmarshalFacProof()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg1FacProof[fromPIdx] = facProof
	case *KGRound2Message2:
		// p.temp.kgRound2Message2s[fromPIdx] = msg
		r2msg2 := msg.Content().(*KGRound2Message2)
		p.temp.r2msg2DecommitX[fromPIdx] = r2msg2.UnmarshalXDeCommitment()
		p.temp.r2msg2DecommitR[fromPIdx] = r2msg2.UnmarshalRDeCommitment()

		proofX, err := r2msg2.UnmarshalXZKProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg2ProofX[fromPIdx] = proofX

		proofR, err := r2msg2.UnmarshalRZKProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msg2ProofR[fromPIdx] = proofR
	case *KGRound3Message1:
		r3msg1 := msg.Content().(*KGRound3Message1)
		var err error
		p.temp.r3msgBigXShare[fromPIdx], err = r3msg1.UnmarshalBigXShare(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r3msgRXProof[fromPIdx], err = r3msg1.UnmarshalAffgProofRX(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r3msgRXD[fromPIdx] = r3msg1.UnmarshalDjiRX()
		p.temp.r3msgRXF[fromPIdx] = r3msg1.UnmarshalFjiRX()
		p.temp.r3msgProofLogstar[fromPIdx], err = r3msg1.UnmarshalLogstarProof(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
	case *KGRound4Message1:
		r4msg1 := msg.Content().(*KGRound4Message1)
		var err error
		p.temp.r4msgRXShare[fromPIdx] = r4msg1.UnmarshalRXShare()
		p.temp.r4msgBigRXShare[fromPIdx], err = r4msg1.UnmarshalBigRXShare(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r4msgProofLogstars[fromPIdx], err = r4msg1.UnmarshalProofLogstar(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
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
