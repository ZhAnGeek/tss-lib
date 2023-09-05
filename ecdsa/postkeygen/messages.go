// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
	zkpfac "github.com/Safulet/tss-lib-private/crypto/zkp/fac"
	zkpmod "github.com/Safulet/tss-lib-private/crypto/zkp/mod"
	zkpprm "github.com/Safulet/tss-lib-private/crypto/zkp/prm"
	"github.com/Safulet/tss-lib-private/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1MessageAck)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound3Message1)(nil),
	}
)

func NewAckMessage(from *tss.PartyID) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1MessageAck{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1MessageAck) ValidateBasic() bool {
	return true
}

func (m *KGRound1MessageAck) RoundNumber() int {
	return 1
}

// ----- //

func NewKGRound2Message1(
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
	proofPrm *zkpprm.ProofPrm,
	proofMod *zkpmod.ProofMod,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	proofPrmBz := proofPrm.Bytes()
	proofModBz := proofMod.Bytes()
	content := &KGRound2Message1{
		PaillierN: paillierPK.N.Bytes(),
		NTilde:    nTildeI.Bytes(),
		H1:        h1I.Bytes(),
		H2:        h2I.Bytes(),
		PrmProof:  proofPrmBz[:],
		ModProof:  proofModBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2()) &&
		common.NonEmptyMultiBytes(m.GetPrmProof(), zkpprm.ProofPrmBytesParts) &&
		common.NonEmptyMultiBytes(m.GetModProof(), zkpmod.ProofModBytesParts)
}

func (m *KGRound2Message1) RoundNumber() int {
	return 2
}

func (m *KGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound2Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KGRound2Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KGRound2Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KGRound2Message1) UnmarshalProofPrm() (*zkpprm.ProofPrm, error) {
	return zkpprm.NewProofFromBytes(m.GetPrmProof())
}

func (m *KGRound2Message1) UnmarshalProofMod() (*zkpmod.ProofMod, error) {
	return zkpmod.NewProofFromBytes(m.GetModProof())
}

func NewKGRound3Message1(
	to, from *tss.PartyID,
	FacProof *zkpfac.ProofFac,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	FacProofBz := FacProof.Bytes()
	content := &KGRound3Message1{
		FacProof: FacProofBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message1) ValidateBasic() bool {
	return m != nil && common.NonEmptyMultiBytes(m.FacProof, zkpfac.ProofFacBytesParts)
}

func (m *KGRound3Message1) RoundNumber() int {
	return 3
}

func (m *KGRound3Message1) UnmarshalFacProof() (*zkpfac.ProofFac, error) {
	return zkpfac.NewProofFromBytes(m.GetFacProof())
}
