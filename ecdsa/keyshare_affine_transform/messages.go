// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keyshare_affine_transform

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KTRound1Message)(nil),
		(*KTRound2Message1)(nil),
		(*KTRound2Message2)(nil),
		(*KTRound3Message)(nil),
	}
)

// ----- //

func NewKTRound1Message(
	from *tss.PartyID,
	VHash *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KTRound1Message{
		VHash: VHash.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KTRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetVHash())
}

func (m *KTRound1Message) RoundNumber() int {
	return 1
}

func (m *KTRound1Message) UnmarshalVHash() *big.Int {
	return new(big.Int).SetBytes(m.GetVHash())
}

// ----- //

func NewKTRound2Message1(
	from *tss.PartyID,
	vs vss.Vs,
	Ai *crypto.ECPoint,
	rid, cmtRandomness *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	vs_flat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return nil
	}
	vsbzs := make([][]byte, len(vs_flat))
	for i, item := range vs_flat {
		vsbzs[i] = item.Bytes()
	}
	AiBzs := Ai.Bytes()
	content := &KTRound2Message1{
		Vs:            vsbzs[:],
		Ai:            AiBzs[:],
		Rid:           rid.Bytes(),
		CmtRandomness: cmtRandomness.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KTRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetVs()) &&
		common.NonEmptyMultiBytes(m.GetAi(), 2) &&
		common.NonEmptyBytes(m.GetRid()) &&
		common.NonEmptyBytes(m.GetCmtRandomness())
}

func (m *KTRound2Message1) RoundNumber() int {
	return 2
}

func (m *KTRound2Message1) UnmarshalVs(ec elliptic.Curve) ([]*crypto.ECPoint, error) {
	bzs := m.GetVs()
	vs_points := make([]*big.Int, len(bzs))
	for i, item := range m.GetVs() {
		vs_points[i] = new(big.Int).SetBytes(item)
	}
	vs, err := crypto.UnFlattenECPoints(ec, vs_points)
	if err != nil {
		return nil, err
	}
	return vs, nil
}

func (m *KTRound2Message1) UnmarshalA(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetAi())
}

func (m *KTRound2Message1) UnmarshalRid() *big.Int {
	return new(big.Int).SetBytes(m.GetRid())
}

func (m *KTRound2Message1) UnmarshalCmtRandomness() *big.Int {
	return new(big.Int).SetBytes(m.GetCmtRandomness())
}

// ----- //

func NewKTRound2Message2(
	to, from *tss.PartyID,
	share *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &KTRound2Message2{
		Share: share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KTRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare())
}

func (m *KTRound2Message2) RoundNumber() int {
	return 2
}

func (m *KTRound2Message2) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.GetShare())
}

// ----- //

func NewKTRound3Message(
	from *tss.PartyID,
	proofSch *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	proofBzs := proofSch.Bytes()
	content := &KTRound3Message{
		SchProof: proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KTRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetSchProof(), zkpsch.ProofSchBytesParts)
}

func (m *KTRound3Message) RoundNumber() int {
	return 3
}

func (m *KTRound3Message) UnmarshalProofSch(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetSchProof())
}
