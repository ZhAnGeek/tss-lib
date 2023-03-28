// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	cmt "github.com/Safulet/tss-lib-private/crypto/commitments"
	zkpaffg "github.com/Safulet/tss-lib-private/crypto/zkp/affg"
	zkpenc "github.com/Safulet/tss-lib-private/crypto/zkp/enc"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tss"
)

// These messages were generated from Protocol Buffers definitions into kcdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message1)(nil),
		(*SignRound3Message1)(nil),
		(*SignRound4Message1)(nil),
	}
)

// ----- //

func NewSignRound1Message(
	from *tss.PartyID,
	kcommitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		KCommitment: kcommitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil && m.KCommitment != nil &&
		common.NonEmptyBytes(m.GetKCommitment())
}

func (m *SignRound1Message) RoundNumber() int {
	return 1
}

func (m *SignRound1Message) UnmarshalKCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetKCommitment())
}

// ----- //

func NewSignRound2Message1(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proofK *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	proofKBzs := proofK.Bytes()
	content := &SignRound2Message1{
		ProofK:        proofKBzs[:],
		KDeCommitment: dcBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message1) ValidateBasic() bool {
	return m != nil && m.KDeCommitment != nil &&
		common.NonEmptyMultiBytes(m.GetKDeCommitment(), 3) &&
		common.NonEmptyMultiBytes(m.GetProofK(), zkpsch.ProofSchBytesParts)

}

func (m *SignRound2Message1) RoundNumber() int {
	return 2
}

func (m *SignRound2Message1) UnmarshalKDeCommitment() []*big.Int {
	deComBzs := m.GetKDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *SignRound2Message1) UnmarshalZKProofK(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProofK())
}

// ----- //

func NewSignRound3Message1(
	from *tss.PartyID,
	K, X *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message1{
		K: K.Bytes(),
		X: X.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.K) &&
		common.NonEmptyBytes(m.X)
}

func (m *SignRound3Message1) RoundNumber() int {
	return 3
}

func (m *SignRound3Message1) UnmarshalK() *big.Int {
	return new(big.Int).SetBytes(m.K)
}
func (m *SignRound3Message1) UnmarshalX() *big.Int {
	return new(big.Int).SetBytes(m.X)
}

func NewSignRound3Message2(
	to, from *tss.PartyID,
	EncProof *zkpenc.ProofEnc,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := EncProof.Bytes()
	content := &SignRound3Message2{
		EncProof: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.EncProof, zkpenc.ProofEncBytesParts)
}

func (m *SignRound3Message2) RoundNumber() int {
	return 3
}

func (m *SignRound3Message2) UnmarshalEncProof() (*zkpenc.ProofEnc, error) {
	return zkpenc.NewProofFromBytes(m.GetEncProof())
}

func NewSignRound4Message1(
	to, from *tss.PartyID,
	BigXShare *crypto.ECPoint,
	DjiKX *big.Int,
	FjiKX *big.Int,
	AffgProofKX *zkpaffg.ProofAffg,
	LogstarProof *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigXShareBytes := BigXShare.Bytes()
	AffgRXBz := AffgProofKX.Bytes()
	LogstarBz := LogstarProof.Bytes()
	content := &SignRound4Message1{
		BigXShare:    BigXShareBytes[:],
		DjiKX:        DjiKX.Bytes(),
		FjiKX:        FjiKX.Bytes(),
		AffgProofKX:  AffgRXBz[:],
		LogstarProof: LogstarBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.BigXShare, 2) &&
		common.NonEmptyBytes(m.DjiKX) &&
		common.NonEmptyBytes(m.FjiKX) &&
		common.NonEmptyMultiBytes(m.AffgProofKX, zkpaffg.ProofAffgBytesParts) &&
		common.NonEmptyMultiBytes(m.LogstarProof, zkplogstar.ProofLogstarBytesParts)
}

func (m *SignRound4Message1) RoundNumber() int {
	return 4
}

func (m *SignRound4Message1) UnmarshalBigXShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigXShare())
}

func (m *SignRound4Message1) UnmarshalDjiKX() *big.Int {
	return new(big.Int).SetBytes(m.GetDjiKX())
}

func (m *SignRound4Message1) UnmarshalFjiKX() *big.Int {
	return new(big.Int).SetBytes(m.GetFjiKX())
}

func (m *SignRound4Message1) UnmarshalAffgProofRX(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
	return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofKX())
}

func (m *SignRound4Message1) UnmarshalLogstarProof(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetLogstarProof())
}

func NewSignRound5Message1(
	to, from *tss.PartyID,
	KXShare *big.Int,
	BigKXShare *crypto.ECPoint,
	ProofLogstar *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigKXShareBzs := BigKXShare.Bytes()
	ProofBz := ProofLogstar.Bytes()
	content := &SignRound5Message1{
		KXShare:      KXShare.Bytes(),
		BigKXShare:   BigKXShareBzs[:],
		ProofLogstar: ProofBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound5Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetKXShare()) &&
		common.NonEmptyMultiBytes(m.GetBigKXShare(), 2) &&
		common.NonEmptyMultiBytes(m.GetProofLogstar(), zkplogstar.ProofLogstarBytesParts)
}

func (m *SignRound5Message1) RoundNumber() int {
	return 5
}

func (m *SignRound5Message1) UnmarshalKXShare() *big.Int {
	return new(big.Int).SetBytes(m.GetKXShare())
}

func (m *SignRound5Message1) UnmarshalBigKXShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigKXShare())
}

func (m *SignRound5Message1) UnmarshalProofLogstar(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetProofLogstar())
}
