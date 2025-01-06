// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	cmt "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tss"
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
	RPubKey *crypto.ECPoint,
	Rvct cmt.HashCommitment,
	ssid []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		SigPubX:        PubKey.X().Bytes(),
		SigPubY:        PubKey.Y().Bytes(),
		SigVCommitment: vct.Bytes(),
		RPubX:          RPubKey.X().Bytes(),
		RPubY:          RPubKey.Y().Bytes(),
		RVCommitment:   Rvct.Bytes(),
		Ssid:           ssid,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SigPubX) &&
		common.NonEmptyBytes(m.SigPubY) &&
		common.NonEmptyBytes(m.SigVCommitment) &&
		common.NonEmptyBytes(m.RPubX) &&
		common.NonEmptyBytes(m.RPubY) &&
		common.NonEmptyBytes(m.RVCommitment)
}

func (m *DGRound1Message) UnmarshalSigPubKey(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.SigPubX),
		new(big.Int).SetBytes(m.SigPubY))
}

func (m *DGRound1Message) UnmarshalRPubKey(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.RPubX),
		new(big.Int).SetBytes(m.RPubY))
}

func (m *DGRound1Message) UnmarshalSigVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetSigVCommitment())
}

func (m *DGRound1Message) UnmarshalRVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetRVCommitment())
}

func (m *DGRound1Message) UnmarshalSSID() []byte {
	return m.GetSsid()
}

func (m *DGRound1Message) RoundNumber() int {
	return 1
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
	sigShare *vss.Share,
	rShare *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		SigShare: sigShare.Share.Bytes(),
		RShare:   rShare.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SigShare) &&
		common.NonEmptyBytes(m.RShare)
}

func (m *DGRound3Message1) RoundNumber() int {
	return 3
}

// ----- //

func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	sigVdct cmt.HashDeCommitment,
	sigProof *zkpsch.ProofSch,
	rVdct cmt.HashDeCommitment,
	rProof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	sigProofBzs := sigProof.Bytes()
	sigVDctBzs := common.BigIntsToBytes(sigVdct)
	rProofBzs := rProof.Bytes()
	rVDctBzs := common.BigIntsToBytes(rVdct)
	content := &DGRound3Message2{
		SigDecommitment: sigVDctBzs,
		SigProof:        sigProofBzs[:],
		RDecommitment:   rVDctBzs,
		RProof:          rProofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.SigDecommitment) &&
		common.NonEmptyMultiBytes(m.RDecommitment)
}

func (m *DGRound3Message2) UnmarshalSigDecommitment() cmt.HashDeCommitment {
	deComBzs := m.GetSigDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *DGRound3Message2) UnmarshalRDecommitment() cmt.HashDeCommitment {
	deComBzs := m.GetRDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *DGRound3Message2) UnmarshalSigZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetSigProof())
}

func (m *DGRound3Message2) UnmarshalRZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetRProof())
}

func (m *DGRound3Message2) RoundNumber() int {
	return 3
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
