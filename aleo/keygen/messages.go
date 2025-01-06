// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	cmt "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
	}
)

// ----- //

func NewKGRound1Message(from *tss.PartyID, ct1, ct2 cmt.HashCommitment) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1Message{
		SigCommitment: ct1.Bytes(),
		RCommitment:   ct2.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetSigCommitment()) && common.NonEmptyBytes(m.GetRCommitment())
}

func (m *KGRound1Message) RoundNumber() int {
	return 1
}

func (m *KGRound1Message) UnmarshalSigCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetSigCommitment())
}

func (m *KGRound1Message) UnmarshalRCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetRCommitment())
}

// ----- //

func NewKGRound2Message1(
	to, from *tss.PartyID,
	sigShare *vss.Share,
	rShare *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &KGRound2Message1{
		SigShare: sigShare.Share.Bytes(),
		RShare:   rShare.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetSigShare()) && common.NonEmptyBytes(m.GetRShare())
}

func (m *KGRound2Message1) RoundNumber() int {
	return 2
}

func (m *KGRound2Message1) UnmarshalSigShare() *big.Int {
	return new(big.Int).SetBytes(m.SigShare)
}

func (m *KGRound2Message1) UnmarshalRShare() *big.Int {
	return new(big.Int).SetBytes(m.RShare)
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	sigDeCommitment cmt.HashDeCommitment,
	sigProof *zkpsch.ProofSch,
	rDeCommitment cmt.HashDeCommitment,
	rProof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs1 := common.BigIntsToBytes(sigDeCommitment)
	proofBzs1 := sigProof.Bytes()
	dcBzs2 := common.BigIntsToBytes(rDeCommitment)
	proofBzs2 := rProof.Bytes()
	content := &KGRound2Message2{
		SigDeCommitment: dcBzs1,
		SigProof:        proofBzs1[:],
		RDeCommitment:   dcBzs2,
		RProof:          proofBzs2[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetSigDeCommitment()) &&
		common.NonEmptyMultiBytes(m.GetRDeCommitment()) &&
		common.NonEmptyMultiBytes(m.SigProof, zkpsch.ProofSchBytesParts) &&
		common.NonEmptyMultiBytes(m.RProof, zkpsch.ProofSchBytesParts)
}

func (m *KGRound2Message2) RoundNumber() int {
	return 2
}

func (m *KGRound2Message2) UnmarshalSigDeCommitment() []*big.Int {
	deComBzs := m.GetSigDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalRDeCommitment() []*big.Int {
	deComBzs := m.GetRDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalSigZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetSigProof())
}

func (m *KGRound2Message2) UnmarshalRZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetRProof())
}
