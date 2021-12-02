// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpenc "github.com/binance-chain/tss-lib/crypto/zkp/enc"
	zkpmulstar "github.com/binance-chain/tss-lib/crypto/zkp/mulstar"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*IdentificationRound1Message)(nil),
	}
)

func NewSignRound1Message(
	from *tss.PartyID,
	SigmaShare *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		SigmaShare: SigmaShare.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SigmaShare)
}

func (m *SignRound1Message) UnmarshalSigmaShare() *big.Int {
	return new(big.Int).SetBytes(m.GetSigmaShare())
}

// ----- //
func NewIdentificationRound1Message(
	to, from *tss.PartyID,
	H *big.Int,
	MulProof *zkpmulstar.ProofMulstar,
	Djis []*big.Int,
	Fjis []*big.Int,
	DjiProofs []*zkpaffg.ProofAffg,
	DecProof *zkpdec.ProofDec,
	DeltaShareEnc *big.Int,
	Q3Enc *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	MulProofBzs := MulProof.Bytes()
	DjisBzs := make([][]byte, len(Djis))
	for i, item := range Djis {
		if item != nil {
			DjisBzs[i] = Djis[i].Bytes()
		}
	}
	FjisBzs := make([][]byte, len(Fjis))
	for i, item := range Fjis {
		if item != nil {
			FjisBzs[i] = Fjis[i].Bytes()
		}
	}
	DjiProofsBzs := make([][]byte, len(DjiProofs)*zkpaffg.ProofAffgBytesParts)
	DecProofBzs := DecProof.Bytes()
	for i, item := range DjiProofs {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				DjiProofsBzs[i*zkpenc.ProofEncBytesParts+j] = itemBzs[j]
			}
		}
	}
	content := &IdentificationRound1Message{
		H:             H.Bytes(),
		MulProof:      MulProofBzs[:],
		Djis:          DjisBzs,
		Fjis:          FjisBzs,
		DjiProofs:     DjiProofsBzs,
		DecProof:      DecProofBzs[:],
		Q3Enc:         Q3Enc.Bytes(),
		DeltaShareEnc: DeltaShareEnc.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.H) &&
		common.NonEmptyMultiBytes(m.MulProof, zkpmulstar.ProofMulstarBytesParts) &&
		common.NonEmptyMultiBytes(m.Djis) &&
		common.NonEmptyMultiBytes(m.Fjis) &&
		common.NonEmptyMultiBytes(m.DjiProofs) &&
		common.NonEmptyMultiBytes(m.DecProof, zkpdec.ProofDecBytesParts)
}

func (m *IdentificationRound1Message) UnmarshalH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *IdentificationRound1Message) UnmarshalProofMul() (*zkpmulstar.ProofMulstar, error) {
	return zkpmulstar.NewProofFromBytes(m.GetMulProof())
}

func (m *IdentificationRound1Message) UnmarshalDjis() []*big.Int {
	DjisBzs := m.GetDjis()
	Djis := make([]*big.Int, len(DjisBzs))
	for i := range Djis {
		Bzs := DjisBzs[i]
		if Bzs != nil {
			Djis[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	return Djis
}

func (m *IdentificationRound1Message) UnmarshalFjis() []*big.Int {
	FjisBzs := m.GetFjis()
	Fjis := make([]*big.Int, len(FjisBzs))
	for i := range Fjis {
		Bzs := FjisBzs[i]
		if Bzs != nil {
			Fjis[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	return Fjis
}

func (m *IdentificationRound1Message) UnmarshalDjiProofs(ec elliptic.Curve) []*zkpaffg.ProofAffg {
	DjiProofsBzs := m.GetDjiProofs()
	DjiProofs := make([]*zkpaffg.ProofAffg, len(DjiProofsBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range DjiProofs {
		if DjiProofsBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, DjiProofsBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err == nil { // continue if error occurs
				DjiProofs[i] = item
			}
		}
	}
	return DjiProofs
}

func (m *IdentificationRound1Message) UnmarshalProofDec() (*zkpdec.ProofDec, error) {
	return zkpdec.NewProofFromBytes(m.GetDecProof())
}

func (m *IdentificationRound1Message) UnmarshalDeltaShareEnc() *big.Int {
	return new(big.Int).SetBytes(m.GetDeltaShareEnc())
}

func (m *IdentificationRound1Message) UnmarshalQ3Enc() *big.Int {
	return new(big.Int).SetBytes(m.GetQ3Enc())
}
