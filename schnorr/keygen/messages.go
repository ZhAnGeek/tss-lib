// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	cmt "github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tss"
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

func NewKGRound1Message(from *tss.PartyID, ct cmt.HashCommitment) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1Message{
		Commitment: ct.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetCommitment())
}

func (m *KGRound1Message) RoundNumber() int {
	return 1
}

func (m *KGRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &KGRound2Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare())
}

func (m *KGRound2Message1) RoundNumber() int {
	return 2
}

func (m *KGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	proofBzs := proof.Bytes()
	content := &KGRound2Message2{
		DeCommitment: dcBzs,
		Proof:        proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment()) &&
		common.NonEmptyMultiBytes(m.Proof, zkpsch.ProofSchBytesParts)
}

func (m *KGRound2Message2) RoundNumber() int {
	return 2
}

func (m *KGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProof())
}