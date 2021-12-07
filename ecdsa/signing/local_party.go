// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpmulstar "github.com/binance-chain/tss-lib/crypto/zkp/mulstar"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/presigning"
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

		keys keygen.LocalPartySaveData
		temp localTempData

		predata *presigning.PreSignatureData
		data    common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.SignatureData
		dump chan<- *LocalDumpPB
		startRndNum int
	}

	localTempData struct {
		// temp data (thrown away after sign) 
		// prepare
		w                   *big.Int
		BigWs               []*crypto.ECPoint
		m                   *big.Int
		KeyDerivationDelta  *big.Int

		// preSig
		ssid                []byte
		KShare              *big.Int
		ChiShare            *big.Int
		BigR                *crypto.ECPoint

		// sign1
		SigmaShare          *big.Int

		// identification1
		K                   *big.Int
		r1msgK              []*big.Int
		ChiShareAlphas      []*big.Int
		ChiShareBetas       []*big.Int
		r2msgChiD           []*big.Int

		// for identification
		ChiMtAFs            []*big.Int
		ChiMtADs            []*big.Int
		ChiMtADProofs       []*zkpaffg.ProofAffg

		// message store
		r4msgSigmaShare     []*big.Int

		r5msgH              []*big.Int
		r5msgProofMulstar   []*zkpmulstar.ProofMulstar
		r5msgSigmaShareEnc  []*big.Int //TODO remove
		r5msgProofDec       []*zkpdec.ProofDec
		r5msgDjis           [][]*big.Int
		r5msgFjis           [][]*big.Int
		//r5msgQ3Enc          []*big.Int
	}

	LocalDump struct {
		Temp *localTempData
		RoundNum int
		Index int
	}
)


func NewLocalParty(
	predata *presigning.PreSignatureData,
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
	dump chan<- *LocalDumpPB,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty:          new(tss.BaseParty),
		params:             params,
		keys:               keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		predata:            predata,
		temp:               localTempData{},
		out:                out,
		end:                end,
		dump:               dump,
	}
	p.temp.m = msg
	p.startRndNum = 1
	// temp data init
	p.temp.KeyDerivationDelta = keyDerivationDelta
	p.temp.BigWs = make([]*crypto.ECPoint, partyCount)

	p.temp.ChiShareAlphas = make([]*big.Int, partyCount)
	p.temp.ChiShareBetas = make([]*big.Int, partyCount)
	p.temp.r2msgChiD = make([]*big.Int, partyCount)
	// for identification
	p.temp.ChiMtAFs = make([]*big.Int, partyCount)
	p.temp.ChiMtADs = make([]*big.Int, partyCount)
	p.temp.ChiMtADProofs = make([]*zkpaffg.ProofAffg, partyCount)

	p.temp.r4msgSigmaShare = make([]*big.Int, partyCount)

	p.temp.r5msgH = make([]*big.Int, partyCount)
	p.temp.r5msgProofMulstar = make([]*zkpmulstar.ProofMulstar, partyCount)
	p.temp.r5msgSigmaShareEnc = make([]*big.Int, partyCount)
	p.temp.r5msgProofDec = make([]*zkpdec.ProofDec, partyCount)
	p.temp.r5msgDjis = make([][]*big.Int, partyCount)
	p.temp.r5msgFjis = make([][]*big.Int, partyCount)
	//p.temp.r5msgQ3Enc = make([]*big.Int, partyCount)

	if p.params.NeedsIdentifaction() {
		trans, err := predata.UnmarshalTrans(p.params.EC())
		if err == nil {
			p.temp.K = trans.K
			p.temp.r1msgK = trans.R1msgK
			p.temp.ChiShareAlphas = trans.ChiShareAlphas
			p.temp.ChiShareBetas = trans.ChiShareBetas
			p.temp.r2msgChiD = trans.R2msgChiD

			p.temp.ChiMtAFs = trans.ChiMtAFs
			p.temp.ChiMtADs = trans.ChiMtADs
			p.temp.ChiMtADProofs = trans.ChiMtADProofs
		}
	}

	return p
}

func RestoreLocalParty(
	predata *presigning.PreSignatureData,
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	du *LocalDumpPB,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
	dump chan<- *LocalDumpPB,
) (tss.Party, *tss.Error) {
	//partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty:          new(tss.BaseParty),
		params:             params,
		keys:               keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:               localTempData{},
		out:                out,
		end:                end,
		dump:               dump,
	}
	//p.startRndNum = int(du.RoundNum)
	//p.temp = *du.Temp
	p.startRndNum = du.UnmarshalRoundNum()
	dtemp, err := du.UnmarshalLocalTemp(p.params.EC())
	if err != nil {
		return nil, tss.NewError(err, TaskName, p.startRndNum, p.PartyID())
	}
	p.temp = *dtemp

	if params.NeedsIdentifaction() {
		trans, err := predata.UnmarshalTrans(p.params.EC())
		if err == nil {
			p.temp.K = trans.K
			p.temp.r1msgK = trans.R1msgK
			p.temp.ChiShareAlphas = trans.ChiShareAlphas
			p.temp.ChiShareBetas = trans.ChiShareBetas
			p.temp.r2msgChiD = trans.R2msgChiD

			p.temp.ChiMtAFs = trans.ChiMtAFs
			p.temp.ChiMtADs = trans.ChiMtADs
			p.temp.ChiMtADProofs = trans.ChiMtADProofs
		}
	}

	errb := tss.BaseRestore(p, TaskName)
	if errb != nil {
		return nil, errb
	}
	return p, nil
}

func (p *LocalParty) FirstRound() tss.Round {
	newRound := []interface{}{newRound1, newRound2, newRound3, newRound4}
	return newRound[p.startRndNum-1].(func(*tss.Parameters, *keygen.LocalPartySaveData, *presigning.PreSignatureData, *common.SignatureData, *localTempData, chan<- tss.Message, chan<- common.SignatureData, chan<- *LocalDumpPB) tss.Round)(p.params, &p.keys, p.predata, &p.data, &p.temp, p.out, p.end, p.dump)
}

func (p *LocalParty) Start() *tss.Error {
	if p.startRndNum == 1 {
		return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
			round1, ok := round.(*sign1)
			if !ok {
				return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
			}
			if err := round1.prepare(); err != nil {
				return round.WrapError(err)
			}
			return nil
		})
	}
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

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
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
	case *SignRound1Message:
		r4msg := msg.Content().(*SignRound1Message)
		p.temp.r4msgSigmaShare[fromPIdx] = r4msg.UnmarshalSigmaShare()
	case *IdentificationRound1Message:
		r5msg := msg.Content().(*IdentificationRound1Message)
		p.temp.r5msgH[fromPIdx] = r5msg.UnmarshalH()
		//p.temp.r5msgSigmaShareEnc[fromPIdx] = r5msg.UnmarshalSigmaShareEnc()
		proofMulstar, err := r5msg.UnmarshalProofMul()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r5msgProofMulstar[fromPIdx] = proofMulstar
		proofDec, err := r5msg.UnmarshalProofDec()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r5msgProofDec[fromPIdx] = proofDec
		p.temp.r5msgDjis[fromPIdx] = r5msg.UnmarshalDjis()
		p.temp.r5msgFjis[fromPIdx] = r5msg.UnmarshalFjis()
		//p.temp.r5msgQ3Enc[fromPIdx] = r5msg.UnmarshalQ3Enc()
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
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
