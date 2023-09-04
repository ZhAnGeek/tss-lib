// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	cmt "github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
	}
)

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	PubKey *crypto.ECPoint,
	vct cmt.HashCommitment,
	ssid []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		PubX:        PubKey.X().Bytes(),
		PubY:        PubKey.Y().Bytes(),
		VCommitment: vct.Bytes(),
		Ssid:        ssid,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.PubX) &&
		common.NonEmptyBytes(m.PubY) &&
		common.NonEmptyBytes(m.VCommitment) &&
		common.NonEmptyBytes(m.Ssid)
}

func (m *DGRound1Message) RoundNumber() int {
	return 1
}

func (m *DGRound1Message) UnmarshalPubKey(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.PubX),
		new(big.Int).SetBytes(m.PubY))
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

func (m *DGRound1Message) UnmarshalSSID() []byte {
	return m.GetSsid()
}

// ----- //

func NewDGRound2Message(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &DGRound2Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message) ValidateBasic() bool {
	return true
}

func (m *DGRound2Message) RoundNumber() int {
	return 2
}

// ----- //

func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

func (m *DGRound3Message1) RoundNumber() int {
	return 3
}

// ----- //

func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
	proof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	proofBzs := proof.Bytes()
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
		Proof:         proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *DGRound3Message2) RoundNumber() int {
	return 3
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *DGRound3Message2) UnmarshalZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProof())
}

// ----- //

func NewDGRound4Message(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message) ValidateBasic() bool {
	return true
}

func (m *DGRound4Message) RoundNumber() int {
	return 4
}
