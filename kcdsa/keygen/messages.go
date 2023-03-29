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
	"github.com/Safulet/tss-lib-private/crypto"
	cmt "github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	zkpaffg "github.com/Safulet/tss-lib-private/crypto/zkp/affg"
	zkpenc "github.com/Safulet/tss-lib-private/crypto/zkp/enc"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	zkpmod "github.com/Safulet/tss-lib-private/crypto/zkp/mod"
	zkpprm "github.com/Safulet/tss-lib-private/crypto/zkp/prm"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message1)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
		(*KGRound3Message1)(nil),
		(*KGRound4Message1)(nil),
	}
)

// ----- //

func NewKGRound1Message1(
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
	Ri, Xi *big.Int,
	rct, xct cmt.HashCommitment,
	proofPrm *zkpprm.ProofPrm,
	proofMod *zkpmod.ProofMod,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	proofPrmBz := proofPrm.Bytes()
	proofModBz := proofMod.Bytes()
	content := &KGRound1Message1{
		PaillierN:   paillierPK.N.Bytes(),
		NTilde:      nTildeI.Bytes(),
		H1:          h1I.Bytes(),
		H2:          h2I.Bytes(),
		R:           Ri.Bytes(),
		X:           Xi.Bytes(),
		RCommitment: rct.Bytes(),
		XCommitment: xct.Bytes(),
		PrmProof:    proofPrmBz[:],
		ModProof:    proofModBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2()) &&
		common.NonEmptyBytes(m.GetR()) &&
		common.NonEmptyBytes(m.GetX()) &&
		common.NonEmptyBytes(m.RCommitment) &&
		common.NonEmptyBytes(m.XCommitment) &&
		common.NonEmptyMultiBytes(m.GetPrmProof(), zkpprm.ProofPrmBytesParts) &&
		common.NonEmptyMultiBytes(m.GetModProof(), zkpmod.ProofModBytesParts)
}

func (m *KGRound1Message1) RoundNumber() int {
	return 1
}

func (m *KGRound1Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound1Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KGRound1Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KGRound1Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KGRound1Message1) UnmarshalR() *big.Int {
	return new(big.Int).SetBytes(m.GetR())
}

func (m *KGRound1Message1) UnmarshalX() *big.Int {
	return new(big.Int).SetBytes(m.GetX())
}

func (m *KGRound1Message1) UnmarshalRCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetRCommitment())
}

func (m *KGRound1Message1) UnmarshalXCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetXCommitment())
}

func (m *KGRound1Message1) UnmarshalProofPrm() (*zkpprm.ProofPrm, error) {
	return zkpprm.NewProofFromBytes(m.GetPrmProof())
}

func (m *KGRound1Message1) UnmarshalProofMod() (*zkpmod.ProofMod, error) {
	return zkpmod.NewProofFromBytes(m.GetModProof())
}

func NewKGRound2Message1(
	to, from *tss.PartyID,
	EncProof *zkpenc.ProofEnc,
	RShare, XShare *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	bytes := EncProof.Bytes()
	content := &KGRound2Message1{
		EncProof: bytes[:],
		RShare:   RShare.Share.Bytes(),
		XShare:   XShare.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.EncProof, zkpenc.ProofEncBytesParts)
}

func (m *KGRound2Message1) RoundNumber() int {
	return 2
}

func (m *KGRound2Message1) UnmarshalRShare() *big.Int {
	return new(big.Int).SetBytes(m.RShare)
}

func (m *KGRound2Message1) UnmarshalXShare() *big.Int {
	return new(big.Int).SetBytes(m.XShare)
}

func (m *KGRound2Message1) UnmarshalEncProof() (*zkpenc.ProofEnc, error) {
	return zkpenc.NewProofFromBytes(m.GetEncProof())
}

// ----- //

func NewKGRound3Message1(
	to, from *tss.PartyID,
	BigXShare *crypto.ECPoint,
	DjiRX *big.Int,
	FjiRX *big.Int,
	AffgProofRX *zkpaffg.ProofAffg,
	LogstarProof *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigXShareBytes := BigXShare.Bytes()
	AffgRXBz := AffgProofRX.Bytes()
	LogstarBz := LogstarProof.Bytes()
	content := &KGRound3Message1{
		BigXShare:    BigXShareBytes[:],
		DjiRX:        DjiRX.Bytes(),
		FjiRX:        FjiRX.Bytes(),
		AffgProofRX:  AffgRXBz[:],
		LogstarProof: LogstarBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.BigXShare, 2) &&
		common.NonEmptyBytes(m.DjiRX) &&
		common.NonEmptyBytes(m.FjiRX) &&
		common.NonEmptyMultiBytes(m.AffgProofRX, zkpaffg.ProofAffgBytesParts) &&
		common.NonEmptyMultiBytes(m.LogstarProof, zkplogstar.ProofLogstarBytesParts)
}

func (m *KGRound3Message1) RoundNumber() int {
	return 3
}

func (m *KGRound3Message1) UnmarshalBigXShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigXShare())
}

func (m *KGRound3Message1) UnmarshalDjiRX() *big.Int {
	return new(big.Int).SetBytes(m.GetDjiRX())
}

func (m *KGRound3Message1) UnmarshalFjiRX() *big.Int {
	return new(big.Int).SetBytes(m.GetFjiRX())
}

func (m *KGRound3Message1) UnmarshalAffgProofRX(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
	return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofRX())
}

func (m *KGRound3Message1) UnmarshalLogstarProof(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetLogstarProof())
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	rdeCommitment cmt.HashDeCommitment,
	rproof *zkpsch.ProofSch,
	xdeCommitment cmt.HashDeCommitment,
	xproof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	rdcBzs := common.BigIntsToBytes(rdeCommitment)
	rproofBzs := rproof.Bytes()
	xdcBzs := common.BigIntsToBytes(xdeCommitment)
	xproofBzs := xproof.Bytes()
	content := &KGRound2Message2{
		RDeCommitment: rdcBzs,
		RProof:        rproofBzs[:],
		XDeCommitment: xdcBzs,
		XProof:        xproofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetRDeCommitment()) &&
		common.NonEmptyMultiBytes(m.RProof, zkpsch.ProofSchBytesParts) &&
		common.NonEmptyMultiBytes(m.GetXDeCommitment()) &&
		common.NonEmptyMultiBytes(m.XProof, zkpsch.ProofSchBytesParts)
}

func (m *KGRound2Message2) RoundNumber() int {
	return 2
}

func (m *KGRound2Message2) UnmarshalRDeCommitment() []*big.Int {
	deComBzs := m.GetRDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalXDeCommitment() []*big.Int {
	deComBzs := m.GetXDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalRZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetRProof())
}

func (m *KGRound2Message2) UnmarshalXZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetXProof())
}

func NewKGRound4Message1(
	to, from *tss.PartyID,
	RXShare *big.Int,
	BigRXShare *crypto.ECPoint,
	ProofLogstar *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigRXShareBzs := BigRXShare.Bytes()
	ProofBz := ProofLogstar.Bytes()
	content := &KGRound4Message1{
		RXShare:      RXShare.Bytes(),
		BigRXShare:   BigRXShareBzs[:],
		ProofLogstar: ProofBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound4Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.RXShare) &&
		common.NonEmptyMultiBytes(m.BigRXShare, 2) &&
		common.NonEmptyMultiBytes(m.ProofLogstar, zkplogstar.ProofLogstarBytesParts)
}

func (m *KGRound4Message1) RoundNumber() int {
	return 4
}

func (m *KGRound4Message1) UnmarshalRXShare() *big.Int {
	return new(big.Int).SetBytes(m.GetRXShare())
}

func (m *KGRound4Message1) UnmarshalBigRXShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigRXShare())
}

func (m *KGRound4Message1) UnmarshalProofLogstar(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetProofLogstar())
}
