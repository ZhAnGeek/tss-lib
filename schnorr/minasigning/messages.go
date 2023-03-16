// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package minasigning

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	cmt "github.com/Safulet/tss-lib-private/crypto/commitments"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
	}
)

// ----- //

func NewSignRound1Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil && m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *SignRound1Message) RoundNumber() int {
	return 1
}

func (m *SignRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound2Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proofD *zkpsch.ProofSch,
	proofE *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	proofDBzs := proofD.Bytes()
	proofEBzs := proofE.Bytes()
	content := &SignRound2Message{
		DeCommitment: dcBzs,
		ProofD:       proofDBzs[:],
		ProofE:       proofEBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 5) &&
		common.NonEmptyMultiBytes(m.ProofD, zkpsch.ProofSchBytesParts) &&
		common.NonEmptyMultiBytes(m.ProofE, zkpsch.ProofSchBytesParts)
}

func (m *SignRound2Message) RoundNumber() int {
	return 2
}

func (m *SignRound2Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *SignRound2Message) UnmarshalZKProofD(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProofD())
}

func (m *SignRound2Message) UnmarshalZKProofE(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProofE())
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	zi *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		Zi: zi.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Zi)
}

func (m *SignRound3Message) RoundNumber() int {
	return 3
}

func (m *SignRound3Message) UnmarshalZi() *big.Int {
	return new(big.Int).SetBytes(m.Zi)
}
