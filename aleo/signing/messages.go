// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	cmt "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	zkpeqlog "github.com/Safulet/tss-lib-private/v2/crypto/zkp/eqlog"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tss"
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
	pointV1 *crypto.ECPoint,
	proofV1 *zkpeqlog.ProofEqLog,
	pointV2 *crypto.ECPoint,
	proofV2 *zkpeqlog.ProofEqLog,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	v1bzs := pointV1.Bytes()
	v2bzs := pointV2.Bytes()
	proof1bzs := proofV1.Bytes()
	proof2bzs := proofV2.Bytes()
	content := &SignRound1Message{
		Commitment:  commitment.Bytes(),
		PointVSkSig: v1bzs[:],
		ProofVSkSig: proof1bzs[:],
		PointVRSig:  v2bzs[:],
		ProofVRSig:  proof2bzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil && m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment()) &&
		common.NonEmptyMultiBytes(m.GetPointVSkSig(), 2) &&
		common.NonEmptyMultiBytes(m.GetPointVRSig(), 2) &&
		common.NonEmptyMultiBytes(m.GetProofVSkSig(), zkpeqlog.ProofEqLogBytesParts) &&
		common.NonEmptyMultiBytes(m.GetProofVRSig(), zkpeqlog.ProofEqLogBytesParts)
}

func (m *SignRound1Message) RoundNumber() int {
	return 1
}

func (m *SignRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

func (m *SignRound1Message) UnmarshalPointV1(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetPointVSkSig())
}

func (m *SignRound1Message) UnmarshalPointV2(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetPointVRSig())
}

func (m *SignRound1Message) UnmarshalProof1() (*zkpeqlog.ProofEqLog, error) {
	return zkpeqlog.NewProofFromBytes(m.GetProofVSkSig())
}

func (m *SignRound1Message) UnmarshalProof2() (*zkpeqlog.ProofEqLog, error) {
	return zkpeqlog.NewProofFromBytes(m.GetProofVRSig())
}

// ----- //

func NewSignRound2Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proofD *zkpsch.ProofSch,
	proofE *zkpsch.ProofSch,
	skTag *big.Int,
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
		SkTag:        skTag.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 5) &&
		common.NonEmptyMultiBytes(m.ProofD, zkpsch.ProofSchBytesParts) &&
		common.NonEmptyMultiBytes(m.ProofE, zkpsch.ProofSchBytesParts) &&
		common.NonEmptyBytes(m.SkTag)
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

func (m *SignRound2Message) UnmarshalSkTag() *big.Int {
	return new(big.Int).SetBytes(m.GetSkTag())
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	shareList []*crypto.ECPoint, // first is tvk, then b and gamma
	proofList []*zkpeqlog.ProofEqLog,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	shareBzs := make([][]byte, len(shareList)*2) // each bytes of ecpoints has 2 parts
	for i := range shareList {
		bzs := shareList[i].Bytes()
		shareBzs[2*i] = bzs[0]
		shareBzs[2*i+1] = bzs[1]
	}
	proofBzs := make([][]byte, len(proofList)*zkpeqlog.ProofEqLogBytesParts)
	for i := range proofList {
		bzs := proofList[i].Bytes()
		for j := range bzs {
			proofBzs[i*zkpeqlog.ProofEqLogBytesParts+j] = bzs[j]
		}
	}
	content := &SignRound3Message{
		ShareList: shareBzs,
		ProofList: proofBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.ShareList) &&
		common.NonEmptyMultiBytes(m.ProofList)
}

func (m *SignRound3Message) RoundNumber() int {
	return 3
}

func (m *SignRound3Message) UnmarshalShareList(ec elliptic.Curve) ([]*crypto.ECPoint, error) {
	bzs := m.GetShareList()
	if len(bzs)%2 != 0 {
		return nil, errors.New("shares list size of match")
	}
	n := len(bzs) / 2
	shareList := make([]*crypto.ECPoint, n)
	for i := 0; i < n; i++ {
		var itemBzs [2][]byte
		itemBzs[0] = bzs[2*i]
		itemBzs[1] = bzs[2*i+1]
		point, err := crypto.NewECPointFromBytes(ec, itemBzs[:])
		if err != nil {
			return nil, err
		}
		shareList[i] = point
	}
	return shareList, nil
}

func (m *SignRound3Message) UnmarshalProofList() ([]*zkpeqlog.ProofEqLog, error) {
	bzs := m.GetProofList()
	if len(bzs)%zkpeqlog.ProofEqLogBytesParts != 0 {
		return nil, errors.New("shares list size of match")
	}
	n := len(bzs) / zkpeqlog.ProofEqLogBytesParts
	proofList := make([]*zkpeqlog.ProofEqLog, n)
	for i := 0; i < n; i++ {
		var itemBzs [zkpeqlog.ProofEqLogBytesParts][]byte
		for j := 0; j < zkpeqlog.ProofEqLogBytesParts; j++ {
			itemBzs[j] = bzs[i*zkpeqlog.ProofEqLogBytesParts+j]
		}
		proof, err := zkpeqlog.NewProofFromBytes(itemBzs[:])
		if err != nil {
			return nil, err
		}
		proofList[i] = proof
	}
	return proofList, nil
}

// ----- //

func NewSignRound4Message(
	from *tss.PartyID,
	responseShare *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound4Message{
		ResponseShare: responseShare.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.ResponseShare)
}

func (m *SignRound4Message) RoundNumber() int {
	return 4
}

func (m *SignRound4Message) UnmarshalResponseShare() *big.Int {
	return new(big.Int).SetBytes(m.GetResponseShare())
}

// ----- //

func NewRequestOut(
	challenge *big.Int,
	response *big.Int,
	skTag *big.Int,
	tvk *big.Int,
	tcm *big.Int,
	scm *big.Int,
) *RequestOut {
	content := &RequestOut{
		Challenge: challenge.Bytes(),
		Response:  response.Bytes(),
		SkTag:     skTag.Bytes(),
		Tvk:       tvk.Bytes(),
		Tcm:       tcm.Bytes(),
		Scm:       scm.Bytes(),
	}
	return content
}

func (m *RequestOut) UnmarshalChallenge() *big.Int {
	return new(big.Int).SetBytes(m.GetChallenge())
}

func (m *RequestOut) UnmarshalResponse() *big.Int {
	return new(big.Int).SetBytes(m.GetResponse())
}

func (m *RequestOut) UnmarshalSkTag() *big.Int {
	return new(big.Int).SetBytes(m.GetSkTag())
}

func (m *RequestOut) UnmarshalTvk() *big.Int {
	return new(big.Int).SetBytes(m.GetTvk())
}

func (m *RequestOut) UnmarshalTcm() *big.Int {
	return new(big.Int).SetBytes(m.GetTcm())
}

func (m *RequestOut) UnmarshalScm() *big.Int {
	return new(big.Int).SetBytes(m.GetScm())
}

// ----- //

func NewSDataOut(
	tvk *big.Int,
	skTag *big.Int,
	gR *crypto.ECPoint,
	rHList []*crypto.ECPoint,
	gammaList []*crypto.ECPoint,
) *SDataOut {
	gRBzs := gR.Bytes()
	rHBzs := make([][]byte, len(rHList)*2)
	for i := range rHList {
		bzs := rHList[i].Bytes()
		rHBzs[2*i] = bzs[0]
		rHBzs[2*i+1] = bzs[1]
	}
	gammaBzs := make([][]byte, len(gammaList)*2)
	for i := range gammaList {
		bzs := gammaList[i].Bytes()
		gammaBzs[2*i] = bzs[0]
		gammaBzs[2*i+1] = bzs[1]
	}
	content := &SDataOut{
		Tvk:       tvk.Bytes(),
		SkTag:     skTag.Bytes(),
		GR:        gRBzs[:],
		HRList:    rHBzs,
		GammaList: gammaBzs,
	}
	return content
}

func (m *SDataOut) UnmarshalTvk() *big.Int {
	return new(big.Int).SetBytes(m.GetTvk())
}

func (m *SDataOut) UnmarshalSkTag() *big.Int {
	return new(big.Int).SetBytes(m.GetSkTag())
}

func (m *SDataOut) UnmarshalR(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetGR())
}

func (m *SDataOut) UnmarshalHRList(ec elliptic.Curve) ([]*crypto.ECPoint, error) {
	bzs := m.GetHRList()
	if len(bzs)%2 != 0 {
		return nil, errors.New("size mismatch")
	}
	n := len(bzs) / 2
	rHList := make([]*crypto.ECPoint, n)
	for i := 0; i < n; i++ {
		var itemBzs [2][]byte
		itemBzs[0] = bzs[2*i]
		itemBzs[1] = bzs[2*i+1]
		point, err := crypto.NewECPointFromBytes(ec, itemBzs[:])
		if err != nil {
			return nil, err
		}
		rHList[i] = point
	}
	return rHList, nil
}

func (m *SDataOut) UnmarshalGammaList(ec elliptic.Curve) ([]*crypto.ECPoint, error) {
	bzs := m.GetGammaList()
	if len(bzs)%2 != 0 {
		return nil, errors.New("size mismatch")
	}
	n := len(bzs) / 2
	gammaList := make([]*crypto.ECPoint, n)
	for i := 0; i < n; i++ {
		var itemBzs [2][]byte
		itemBzs[0] = bzs[2*i]
		itemBzs[1] = bzs[2*i+1]
		point, err := crypto.NewECPointFromBytes(ec, itemBzs[:])
		if err != nil {
			return nil, err
		}
		gammaList[i] = point
	}
	return gammaList, nil
}

// ----- //

func NewSignData(
	ssid []byte,
	ri *big.Int,
) *SignData {
	content := &SignData{
		Ssid: ssid,
		R:    ri.Bytes(),
	}
	return content
}

func (m *SignData) UnmarshalSsid() []byte {
	return m.GetSsid()
}

func (m *SignData) UnmarshalRi() *big.Int {
	return new(big.Int).SetBytes(m.GetR())
}
