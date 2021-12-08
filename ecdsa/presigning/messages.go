// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpenc "github.com/binance-chain/tss-lib/crypto/zkp/enc"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	zkpmul "github.com/binance-chain/tss-lib/crypto/zkp/mul"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*PreSignRound1Message)(nil),
		(*PreSignRound2Message)(nil),
		(*PreSignRound3Message)(nil),
		(*IdentificationRound1Message)(nil),
	}
)

// ----- //
func NewPreSignData(
	index int,
	ssid []byte,
	bigR *crypto.ECPoint,
	kShare *big.Int,
	chiShare *big.Int,
	trans *Transcript,
) *PreSignatureData {
	bigRBzs := bigR.Bytes()

	var KBzs []byte
	if trans.K != nil {
		KBzs = trans.K.Bytes()
	}
	r1msgKBzs := make([][]byte, len(trans.R1msgK))
	for i, item := range trans.R1msgK {
		if item != nil {
			r1msgKBzs[i] = item.Bytes()
		}
	}
	ChiShareAlphasBzs := make([][]byte, len(trans.ChiShareAlphas))
	for i, item := range trans.ChiShareAlphas {
		if item != nil {
			ChiShareAlphasBzs[i] = item.Bytes()
		}
	}
	ChiShareBetasBzs := make([][]byte, len(trans.ChiShareBetas))
	for i, item := range trans.ChiShareBetas {
		if item != nil {
			ChiShareBetasBzs[i] = item.Bytes()
		}
	}
	r2msgChiDBzs := make([][]byte, len(trans.R2msgChiD))
	for i, item := range trans.R2msgChiD {
		if item != nil {
			r2msgChiDBzs[i] = item.Bytes()
		}
	}

	ChiMtAFsBzs := make([][]byte, len(trans.ChiMtAFs))
	for i, item := range trans.ChiMtAFs {
		if item != nil {
			ChiMtAFsBzs[i] = item.Bytes()
		}
	}
	ChiMtADsBzs := make([][]byte, len(trans.ChiMtADs))
	for i, item := range trans.ChiMtADs {
		if item != nil {
			ChiMtADsBzs[i] = item.Bytes()
		}
	}
	ChiMtaDProofsBzs := make([][]byte, len(trans.ChiMtADProofs)*zkpaffg.ProofAffgBytesParts)
	for i, item := range trans.ChiMtADProofs {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				ChiMtaDProofsBzs[i*zkpaffg.ProofAffgBytesParts+j] = itemBzs[j]
			}
		}
	}
	content := &PreSignatureData{
		Index:    int32(index),
		Ssid:     ssid,
		BigR:     bigRBzs[:],
		KShare:   kShare.Bytes(),
		ChiShare: chiShare.Bytes(),

		LRK:              KBzs,
		LRr1MsgK:         r1msgKBzs,
		LRChiShareAlphas: ChiShareAlphasBzs,
		LRChiShareBetas:  ChiShareBetasBzs,
		LRr2MsgChiD:      r2msgChiDBzs,

		LRChiMtAFs:      ChiMtAFsBzs,
		LRChiMtADs:      ChiMtADsBzs,
		LRChiMtADProofs: ChiMtaDProofsBzs,
	}
	return content
}

func (m *PreSignatureData) UnmarshalIndex() int {
	return int(m.GetIndex())
}

func (m *PreSignatureData) UnmarshalSsid() []byte {
	return m.GetSsid()
}

func (m *PreSignatureData) UnmarshalBigR(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigR())
}

func (m *PreSignatureData) UnmarshalKShare() *big.Int {
	return new(big.Int).SetBytes(m.GetKShare())
}

func (m *PreSignatureData) UnmarshalChiShare() *big.Int {
	return new(big.Int).SetBytes(m.GetChiShare())
}

func (m *PreSignatureData) UnmarshalTrans(ec elliptic.Curve) (*Transcript, error) {
	KBzs := m.GetLRK()
	var K *big.Int
	if KBzs != nil {
		K = new(big.Int).SetBytes(KBzs)
	}
	r1msgKBzs := m.GetLRr1MsgK()
	r1msgK := make([]*big.Int, len(r1msgKBzs))
	for i := range r1msgK {
		Bzs := r1msgKBzs[i]
		if Bzs != nil {
			r1msgK[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiShareAlphasBzs := m.GetLRChiShareAlphas()
	ChiShareAlphas := make([]*big.Int, len(ChiShareAlphasBzs))
	for i := range ChiShareAlphas {
		Bzs := ChiShareAlphasBzs[i]
		if Bzs != nil {
			ChiShareAlphas[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiShareBetasBzs := m.GetLRChiShareBetas()
	ChiShareBetas := make([]*big.Int, len(ChiShareBetasBzs))
	for i := range ChiShareBetas {
		Bzs := ChiShareBetasBzs[i]
		if Bzs != nil {
			ChiShareBetas[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r2msgChiDBzs := m.GetLRr2MsgChiD()
	r2msgChiD := make([]*big.Int, len(r2msgChiDBzs))
	for i := range r2msgChiD {
		Bzs := r2msgChiDBzs[i]
		if Bzs != nil {
			r2msgChiD[i] = new(big.Int).SetBytes(Bzs)
		}
	}

	ChiMtAFsBzs := m.GetLRChiMtAFs()
	ChiMtAFs := make([]*big.Int, len(ChiMtAFsBzs))
	for i := range ChiMtAFs {
		Bzs := ChiMtAFsBzs[i]
		if Bzs != nil {
			ChiMtAFs[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiMtADsBzs := m.GetLRChiMtADs()
	ChiMtADs := make([]*big.Int, len(ChiMtADsBzs))
	for i := range ChiMtADs {
		Bzs := ChiMtADsBzs[i]
		if Bzs != nil {
			ChiMtADs[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiMtADProofsBzs := m.GetLRChiMtADProofs()
	ChiMtADProofs := make([]*zkpaffg.ProofAffg, len(ChiMtADProofsBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range ChiMtADProofs {
		if ChiMtADProofsBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, ChiMtADProofsBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err != nil {
				return nil, err
			}
			ChiMtADProofs[i] = item
		}
	}

	trans := &Transcript{
		K:              K,
		R1msgK:         r1msgK,
		ChiShareAlphas: ChiShareAlphas,
		ChiShareBetas:  ChiShareBetas,
		R2msgChiD:      r2msgChiD,

		ChiMtAFs:      ChiMtAFs,
		ChiMtADs:      ChiMtADs,
		ChiMtADProofs: ChiMtADProofs,
	}
	return trans, nil
}

func NewPreSignRound1Message(
	to, from *tss.PartyID,
	K *big.Int,
	G *big.Int,
	EncProof *zkpenc.ProofEnc,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := EncProof.Bytes()
	content := &PreSignRound1Message{
		K:        K.Bytes(),
		G:        G.Bytes(),
		EncProof: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.K) &&
		common.NonEmptyBytes(m.G) &&
		common.NonEmptyMultiBytes(m.EncProof, zkpenc.ProofEncBytesParts)
}

func (m *PreSignRound1Message) UnmarshalK() *big.Int {
	return new(big.Int).SetBytes(m.GetK())
}

func (m *PreSignRound1Message) UnmarshalG() *big.Int {
	return new(big.Int).SetBytes(m.GetG())
}

func (m *PreSignRound1Message) UnmarshalEncProof() (*zkpenc.ProofEnc, error) {
	return zkpenc.NewProofFromBytes(m.GetEncProof())
}

// ----- //

func NewPreSignRound2Message(
	to, from *tss.PartyID,
	BigGammaShare *crypto.ECPoint,
	DjiDelta *big.Int,
	FjiDelta *big.Int,
	DjiChi *big.Int,
	FjiChi *big.Int,
	AffgProofDelta *zkpaffg.ProofAffg,
	AffgProofChi *zkpaffg.ProofAffg,
	LogstarProof *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigGammaBytes := BigGammaShare.Bytes()
	AffgDeltaBz := AffgProofDelta.Bytes()
	AffgChiBz := AffgProofChi.Bytes()
	LogstarBz := LogstarProof.Bytes()
	content := &PreSignRound2Message{
		BigGammaShare:  BigGammaBytes[:],
		DjiDelta:       DjiDelta.Bytes(),
		FjiDelta:       FjiDelta.Bytes(),
		DjiChi:         DjiChi.Bytes(),
		FjiChi:         FjiChi.Bytes(),
		AffgProofDelta: AffgDeltaBz[:],
		AffgProofChi:   AffgChiBz[:],
		LogstarProof:   LogstarBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.BigGammaShare, 2) &&
		common.NonEmptyBytes(m.DjiDelta) &&
		common.NonEmptyBytes(m.FjiDelta) &&
		common.NonEmptyBytes(m.DjiChi) &&
		common.NonEmptyBytes(m.FjiChi) &&
		common.NonEmptyMultiBytes(m.AffgProofDelta, zkpaffg.ProofAffgBytesParts) &&
		common.NonEmptyMultiBytes(m.AffgProofChi, zkpaffg.ProofAffgBytesParts) &&
		common.NonEmptyMultiBytes(m.LogstarProof, zkplogstar.ProofLogstarBytesParts)
}

func (m *PreSignRound2Message) UnmarshalBigGammaShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigGammaShare())
}

func (m *PreSignRound2Message) UnmarshalDjiDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetDjiDelta())
}

func (m *PreSignRound2Message) UnmarshalFjiDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetFjiDelta())
}

func (m *PreSignRound2Message) UnmarshalDjiChi() *big.Int {
	return new(big.Int).SetBytes(m.GetDjiChi())
}

func (m *PreSignRound2Message) UnmarshalFjiChi() *big.Int {
	return new(big.Int).SetBytes(m.GetFjiChi())
}

func (m *PreSignRound2Message) UnmarshalAffgProofDelta(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
	return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofDelta())
}

func (m *PreSignRound2Message) UnmarshalAffgProofChi(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
	return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofChi())
}

func (m *PreSignRound2Message) UnmarshalLogstarProof(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetLogstarProof())
}

// ----- //

func NewPreSignRound3Message(
	to, from *tss.PartyID,
	DeltaShare *big.Int,
	BigDeltaShare *crypto.ECPoint,
	ProofLogstar *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigDeltaShareBzs := BigDeltaShare.Bytes()
	ProofBz := ProofLogstar.Bytes()
	content := &PreSignRound3Message{
		DeltaShare:    DeltaShare.Bytes(),
		BigDeltaShare: BigDeltaShareBzs[:],
		ProofLogstar:  ProofBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.DeltaShare) &&
		common.NonEmptyMultiBytes(m.BigDeltaShare, 2) &&
		common.NonEmptyMultiBytes(m.ProofLogstar, zkplogstar.ProofLogstarBytesParts)
}

func (m *PreSignRound3Message) UnmarshalDeltaShare() *big.Int {
	return new(big.Int).SetBytes(m.GetDeltaShare())
}

func (m *PreSignRound3Message) UnmarshalBigDeltaShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigDeltaShare())
}

func (m *PreSignRound3Message) UnmarshalProofLogstar(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetProofLogstar())
}

// ----- //

func NewIdentificationRound1Message(
	to, from *tss.PartyID,
	H *big.Int,
	MulProof *zkpmul.ProofMul,
	Djis []*big.Int,
	Fjis []*big.Int,
	DjiProofs []*zkpaffg.ProofAffg,
	DecProof *zkpdec.ProofDec,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	MulProofBzs := MulProof.Bytes()
	DjisBzs := make([][]byte, len(Djis))
	for i, item := range Djis {
		if item != nil {
			DjisBzs[i] = Djis[i].Bytes()
		}
	}
	FjisBzs := make([][]byte, len(Fjis))
	for i, item := range Fjis {
		if item != nil {
			FjisBzs[i] = Fjis[i].Bytes()
		}
	}
	DjiProofsBzs := make([][]byte, len(DjiProofs)*zkpaffg.ProofAffgBytesParts)
	DecProofBzs := DecProof.Bytes()
	for i, item := range DjiProofs {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				DjiProofsBzs[i*zkpenc.ProofEncBytesParts+j] = itemBzs[j]
			}
		}
	}
	content := &IdentificationRound1Message{
		H:         H.Bytes(),
		MulProof:  MulProofBzs[:],
		Djis:      DjisBzs,
		Fjis:      FjisBzs,
		DjiProofs: DjiProofsBzs,
		DecProof:  DecProofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.H) &&
		common.NonEmptyMultiBytes(m.MulProof, zkpmul.ProofMulBytesParts) &&
		common.NonEmptyMultiBytes(m.Djis) &&
		common.NonEmptyMultiBytes(m.Fjis) &&
		common.NonEmptyMultiBytes(m.DjiProofs) &&
		common.NonEmptyMultiBytes(m.DecProof, zkpdec.ProofDecBytesParts)
}

func (m *IdentificationRound1Message) UnmarshalH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *IdentificationRound1Message) UnmarshalProofMul() (*zkpmul.ProofMul, error) {
	return zkpmul.NewProofFromBytes(m.GetMulProof())
}

func (m *IdentificationRound1Message) UnmarshalDjis() []*big.Int {
	DjisBzs := m.GetDjis()
	Djis := make([]*big.Int, len(DjisBzs))
	for i := range Djis {
		Bzs := DjisBzs[i]
		if Bzs != nil {
			Djis[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	return Djis
}

func (m *IdentificationRound1Message) UnmarshalFjis() []*big.Int {
	FjisBzs := m.GetFjis()
	Fjis := make([]*big.Int, len(FjisBzs))
	for i := range Fjis {
		Bzs := FjisBzs[i]
		if Bzs != nil {
			Fjis[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	return Fjis
}

func (m *IdentificationRound1Message) UnmarshalDjiProofs(ec elliptic.Curve) []*zkpaffg.ProofAffg {
	DjiProofsBzs := m.GetDjiProofs()
	DjiProofs := make([]*zkpaffg.ProofAffg, len(DjiProofsBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range DjiProofs {
		if DjiProofsBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, DjiProofsBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err == nil { // continue if error occurs
				DjiProofs[i] = item
			}
		}
	}
	return DjiProofs
}

func (m *IdentificationRound1Message) UnmarshalProofDec() (*zkpdec.ProofDec, error) {
	return zkpdec.NewProofFromBytes(m.GetDecProof())
}

func NewLocalDumpPB(
	Index int,
	RoundNum int,
	LocalTemp *localTempData,
) *LocalDumpPB {
	var wBzs []byte
	if LocalTemp.w != nil {
		wBzs = LocalTemp.w.Bytes()
	}
	BigWsBzs := make([][]byte, len(LocalTemp.BigWs)*2)
	for i, item := range LocalTemp.BigWs {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < 2; j++ {
				BigWsBzs[i*2+j] = itemBzs[j]
			}
		}
	}
	var KShareBzs []byte
	if LocalTemp.KShare != nil {
		KShareBzs = LocalTemp.KShare.Bytes()
	}

	var BigGammaShareBzs [][]byte
	if LocalTemp.BigGammaShare != nil {
		Bzs := LocalTemp.BigGammaShare.Bytes()
		BigGammaShareBzs = Bzs[:]
	}
	var KBzs []byte
	if LocalTemp.K != nil {
		KBzs = LocalTemp.K.Bytes()
	}
	var GBzs []byte
	if LocalTemp.G != nil {
		GBzs = LocalTemp.G.Bytes()
	}
	var KNonceBzs []byte
	if LocalTemp.KNonce != nil {
		KNonceBzs = LocalTemp.KNonce.Bytes()
	}
	var GNonceBzs []byte
	if LocalTemp.GNonce != nil {
		GNonceBzs = LocalTemp.GNonce.Bytes()
	}

	var GammaShareBzs []byte
	if LocalTemp.GammaShare != nil {
		GammaShareBzs = LocalTemp.GammaShare.Bytes()
	}
	DeltaShareBetasBzs := make([][]byte, len(LocalTemp.DeltaShareBetas))
	for i, item := range LocalTemp.DeltaShareBetas {
		if item != nil {
			DeltaShareBetasBzs[i] = item.Bytes()
		}
	}
	ChiShareBetasBzs := make([][]byte, len(LocalTemp.ChiShareBetas))
	for i, item := range LocalTemp.ChiShareBetas {
		if item != nil {
			ChiShareBetasBzs[i] = item.Bytes()
		}
	}

	var BigGammaBzs [][]byte
	if LocalTemp.BigGamma != nil {
		Bzs := LocalTemp.BigGamma.Bytes()
		BigGammaBzs = Bzs[:]
	}
	DeltaShareAlphasBzs := make([][]byte, len(LocalTemp.DeltaShareAlphas))
	for i, item := range LocalTemp.DeltaShareAlphas {
		if item != nil {
			DeltaShareAlphasBzs[i] = item.Bytes()
		}
	}
	ChiShareAlphasBzs := make([][]byte, len(LocalTemp.ChiShareAlphas))
	for i, item := range LocalTemp.ChiShareAlphas {
		if item != nil {
			ChiShareAlphasBzs[i] = item.Bytes()
		}
	}
	var DeltaShareBzs []byte
	if LocalTemp.DeltaShare != nil {
		DeltaShareBzs = LocalTemp.DeltaShare.Bytes()
	}
	var ChiShareBzs []byte
	if LocalTemp.ChiShare != nil {
		ChiShareBzs = LocalTemp.ChiShare.Bytes()
	}
	var BigDeltaShareBzs [][]byte
	if LocalTemp.BigDeltaShare != nil {
		Bzs := LocalTemp.BigDeltaShare.Bytes()
		BigDeltaShareBzs = Bzs[:]
	}

	var BigRBzs [][]byte
	if LocalTemp.BigR != nil {
		Bzs := LocalTemp.BigR.Bytes()
		BigRBzs = Bzs[:]
	}
	var RxBzs []byte
	if LocalTemp.Rx != nil {
		RxBzs = LocalTemp.Rx.Bytes()
	}
	var SigmaShareBzs []byte
	if LocalTemp.SigmaShare != nil {
		SigmaShareBzs = LocalTemp.SigmaShare.Bytes()
	}

	r1msgGBzs := make([][]byte, len(LocalTemp.r1msgG))
	for i, item := range LocalTemp.r1msgG {
		if item != nil {
			r1msgGBzs[i] = item.Bytes()
		}
	}
	r1msgKBzs := make([][]byte, len(LocalTemp.r1msgK))
	for i, item := range LocalTemp.r1msgK {
		if item != nil {
			r1msgKBzs[i] = item.Bytes()
		}
	}
	r1msgProofBzs := make([][]byte, len(LocalTemp.r1msgProof)*zkpenc.ProofEncBytesParts)
	for i, item := range LocalTemp.r1msgProof {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpenc.ProofEncBytesParts; j++ {
				r1msgProofBzs[i*zkpenc.ProofEncBytesParts+j] = itemBzs[j]
			}
		}
	}

	r2msgBigGammaShareBzs := make([][]byte, len(LocalTemp.r2msgBigGammaShare)*2)
	for i, item := range LocalTemp.r2msgBigGammaShare {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < 2; j++ {
				r2msgBigGammaShareBzs[i*2+j] = itemBzs[j]
			}
		}
	}
	r2msgDeltaDBzs := make([][]byte, len(LocalTemp.r2msgDeltaD))
	for i, item := range LocalTemp.r2msgDeltaD {
		if item != nil {
			r2msgDeltaDBzs[i] = item.Bytes()
		}
	}
	r2msgDeltaFBzs := make([][]byte, len(LocalTemp.r2msgDeltaF))
	for i, item := range LocalTemp.r2msgDeltaF {
		if item != nil {
			r2msgDeltaFBzs[i] = item.Bytes()
		}
	}
	r2msgDeltaProofBzs := make([][]byte, len(LocalTemp.r2msgDeltaProof)*zkpaffg.ProofAffgBytesParts)
	for i, item := range LocalTemp.r2msgDeltaProof {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				r2msgDeltaProofBzs[i*zkpaffg.ProofAffgBytesParts+j] = itemBzs[j]
			}
		}
	}
	r2msgChiDBzs := make([][]byte, len(LocalTemp.r2msgChiD))
	for i, item := range LocalTemp.r2msgChiD {
		if item != nil {
			r2msgChiDBzs[i] = item.Bytes()
		}
	}
	r2msgChiFBzs := make([][]byte, len(LocalTemp.r2msgChiF))
	for i, item := range LocalTemp.r2msgChiF {
		if item != nil {
			r2msgChiFBzs[i] = item.Bytes()
		}
	}
	r2msgChiProofBzs := make([][]byte, len(LocalTemp.r2msgChiProof)*zkpaffg.ProofAffgBytesParts)
	for i, item := range LocalTemp.r2msgChiProof {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				r2msgChiProofBzs[i*zkpaffg.ProofAffgBytesParts+j] = itemBzs[j]
			}
		}
	}
	r2msgProofLogstarBzs := make([][]byte, len(LocalTemp.r2msgProofLogstar)*zkplogstar.ProofLogstarBytesParts)
	for i, item := range LocalTemp.r2msgProofLogstar {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkplogstar.ProofLogstarBytesParts; j++ {
				r2msgProofLogstarBzs[i*zkplogstar.ProofLogstarBytesParts+j] = itemBzs[j]
			}
		}
	}

	r3msgDeltaShareBzs := make([][]byte, len(LocalTemp.r3msgDeltaShare))
	for i, item := range LocalTemp.r3msgDeltaShare {
		if item != nil {
			r3msgDeltaShareBzs[i] = item.Bytes()
		}
	}
	r3msgBigDeltaShareBzs := make([][]byte, len(LocalTemp.r3msgBigDeltaShare)*2)
	for i, item := range LocalTemp.r3msgBigDeltaShare {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < 2; j++ {
				r3msgBigDeltaShareBzs[i*2+j] = itemBzs[j]
			}
		}
	}
	r3msgProofLogstarBzs := make([][]byte, len(LocalTemp.r3msgProofLogstar)*zkplogstar.ProofLogstarBytesParts)
	for i, item := range LocalTemp.r3msgProofLogstar {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkplogstar.ProofLogstarBytesParts; j++ {
				r3msgProofLogstarBzs[i*zkplogstar.ProofLogstarBytesParts+j] = itemBzs[j]
			}
		}
	}

	r4msgSigmaShareBzs := make([][]byte, len(LocalTemp.r4msgSigmaShare))
	for i, item := range LocalTemp.r4msgSigmaShare {
		if item != nil {
			r4msgSigmaShareBzs[i] = item.Bytes()
		}
	}

	DeltaMtAFsBzs := make([][]byte, len(LocalTemp.DeltaMtAFs))
	for i, item := range LocalTemp.DeltaMtAFs {
		if item != nil {
			DeltaMtAFsBzs[i] = item.Bytes()
		}
	}
	DeltaMtADsBzs := make([][]byte, len(LocalTemp.DeltaMtADs))
	for i, item := range LocalTemp.DeltaMtADs {
		if item != nil {
			DeltaMtADsBzs[i] = item.Bytes()
		}
	}
	DeltaMtaDProofsBzs := make([][]byte, len(LocalTemp.DeltaMtADProofs)*zkpaffg.ProofAffgBytesParts)
	for i, item := range LocalTemp.DeltaMtADProofs {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				DeltaMtaDProofsBzs[i*zkpaffg.ProofAffgBytesParts+j] = itemBzs[j]
			}
		}
	}
	ChiMtAFsBzs := make([][]byte, len(LocalTemp.ChiMtAFs))
	for i, item := range LocalTemp.ChiMtAFs {
		if item != nil {
			ChiMtAFsBzs[i] = item.Bytes()
		}
	}
	ChiMtADsBzs := make([][]byte, len(LocalTemp.ChiMtADs))
	for i, item := range LocalTemp.ChiMtADs {
		if item != nil {
			ChiMtADsBzs[i] = item.Bytes()
		}
	}
	ChiMtaDProofsBzs := make([][]byte, len(LocalTemp.ChiMtADProofs)*zkpaffg.ProofAffgBytesParts)
	for i, item := range LocalTemp.ChiMtADProofs {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
				ChiMtaDProofsBzs[i*zkpaffg.ProofAffgBytesParts+j] = itemBzs[j]
			}
		}
	}
	r5msgHBzs := make([][]byte, len(LocalTemp.r5msgH))
	for i, item := range LocalTemp.r5msgH {
		if item != nil {
			r5msgHBzs[i] = item.Bytes()
		}
	}
	r5msgProofMulBzs := make([][]byte, len(LocalTemp.r5msgProofMul)*zkpmul.ProofMulBytesParts)
	for i, item := range LocalTemp.r5msgProofMul {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpmul.ProofMulBytesParts; j++ {
				r5msgProofMulBzs[i*zkpmul.ProofMulBytesParts+j] = itemBzs[j]
			}
		}
	}
	//r5msgDeltaShareEncBzs := make([][]byte, len(LocalTemp.r5msgDeltaShareEnc))
	//for i, item := range LocalTemp.r5msgDeltaShareEnc {
	//	if item != nil {
	//		r5msgDeltaShareEncBzs[i] = item.Bytes()
	//	}
	//}
	r5msgProofDecBzs := make([][]byte, len(LocalTemp.r5msgProofDec)*zkpdec.ProofDecBytesParts)
	for i, item := range LocalTemp.r5msgProofDec {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpdec.ProofDecBytesParts; j++ {
				r5msgProofDecBzs[i*zkpdec.ProofDecBytesParts+j] = itemBzs[j]
			}
		}
	}
	r5msgDjiLen := len(LocalTemp.r5msgDjis)
	r5msgDjisBzs := make([][]byte, r5msgDjiLen*r5msgDjiLen)
	for i, row := range LocalTemp.r5msgDjis {
		for j, item := range row {
			if item != nil {
				r5msgDjisBzs[i*r5msgDjiLen+j] = item.Bytes()
			}
		}
	}
	r5msgFjiLen := len(LocalTemp.r5msgFjis)
	r5msgFjisBzs := make([][]byte, r5msgFjiLen*r5msgFjiLen)
	for i, row := range LocalTemp.r5msgFjis {
		for j, item := range row {
			if item != nil {
				r5msgFjisBzs[i*r5msgFjiLen+j] = item.Bytes()
			}
		}
	}
	//r5msgQ3EncBzs := make([][]byte, len(LocalTemp.r5msgQ3Enc))
	//for i, item := range LocalTemp.r5msgQ3Enc {
	//	if item != nil {
	//		r5msgQ3EncBzs[i] = item.Bytes()
	//	}
	//}

	content := &LocalDumpPB{
		Index:    int32(Index),
		RoundNum: int32(RoundNum),

		LTssid:   LocalTemp.ssid,
		LTw:      wBzs,
		LTBigWs:  BigWsBzs,
		LTKShare: KShareBzs,

		LTBigGammaShare: BigGammaShareBzs,
		LTK:             KBzs,
		LTG:             GBzs,
		LTKNonce:        KNonceBzs,
		LTGNonce:        GNonceBzs,

		LTGammaShare:      GammaShareBzs,
		LTDeltaShareBetas: DeltaShareBetasBzs,
		LTChiShareBetas:   ChiShareBetasBzs,

		LTBigGamma:         BigGammaBzs,
		LTDeltaShareAlphas: DeltaShareAlphasBzs,
		LTChiShareAlphas:   ChiShareAlphasBzs,
		LTDeltaShare:       DeltaShareBzs,
		LTChiShare:         ChiShareBzs,
		LTBigDeltaShare:    BigDeltaShareBzs,

		LTBigR:       BigRBzs,
		LTRx:         RxBzs,
		LTSigmaShare: SigmaShareBzs,

		LTr1MsgG:     r1msgGBzs,
		LTr1MsgK:     r1msgKBzs,
		LTr1MsgProof: r1msgProofBzs,

		LTr2MsgBigGammaShare: r2msgBigGammaShareBzs,
		LTr2MsgDeltaD:        r2msgDeltaDBzs,
		LTr2MsgDeltaF:        r2msgDeltaFBzs,
		LTr2MsgDeltaProof:    r2msgDeltaProofBzs,
		LTr2MsgChiD:          r2msgChiDBzs,
		LTr2MsgChiF:          r2msgChiFBzs,
		LTr2MsgChiProof:      r2msgChiProofBzs,
		LTr2MsgProofLogstar:  r2msgProofLogstarBzs,

		LTr3MsgDeltaShare:    r3msgDeltaShareBzs,
		LTr3MsgBigDeltaShare: r3msgBigDeltaShareBzs,
		LTr3MsgProofLogstar:  r3msgProofLogstarBzs,

		LTr4MsgSigmaShare: r4msgSigmaShareBzs,

		LTDeltaMtAFs:      DeltaMtAFsBzs,
		LTDeltaMtADs:      DeltaMtADsBzs,
		LDDeltaMtADProofs: DeltaMtaDProofsBzs,
		LTChiMtAFs:        ChiMtAFsBzs,
		LTChiMtADs:        ChiMtADsBzs,
		LTChiMtADProofs:   ChiMtaDProofsBzs,
		LTr5MsgH:          r5msgHBzs,
		LTr5MsgProofMul:   r5msgProofMulBzs,
		//LTr6MsgDeltaShareEnc: r6msgDeltaShareEncBzs,
		LTr5MsgProofDec: r5msgProofDecBzs,
		LTr5MsgDjis:     r5msgDjisBzs,
		LTr5MsgFjis:     r5msgFjisBzs,
		//LTr5MsgQ3Enc:         r5msgQ3EncBzs,
	}
	return content
}

func (m *LocalDumpPB) UnmarshalIndex() int {
	return int(m.GetIndex())
}

func (m *LocalDumpPB) UnmarshalRoundNum() int {
	return int(m.GetRoundNum())
}

func (m *LocalDumpPB) UnmarshalLocalTemp(ec elliptic.Curve) (*localTempData, error) {
	ssid := m.GetLTssid()
	wBzs := m.GetLTw()
	var w *big.Int
	if wBzs != nil {
		w = new(big.Int).SetBytes(wBzs)
	}
	BigWsBzs := m.GetLTBigWs()
	BigWs := make([]*crypto.ECPoint, len(BigWsBzs)/2)
	for i := range BigWs {
		if BigWsBzs[i*2] != nil {
			item, err := crypto.NewECPointFromBytes(ec, BigWsBzs[(i*2):(i*2+2)])
			if err != nil {
				return nil, err
			}
			BigWs[i] = item
		}
	}
	KShareBzs := m.GetLTKShare()
	var KShare *big.Int
	if KShareBzs != nil {
		KShare = new(big.Int).SetBytes(KShareBzs)
	}

	BigGammaShareBzs := m.GetLTBigGammaShare()
	var BigGammaShare *crypto.ECPoint
	if BigGammaShareBzs != nil {
		item, err := crypto.NewECPointFromBytes(ec, BigGammaShareBzs)
		if err != nil {
			return nil, err
		}
		BigGammaShare = item
	}
	KBzs := m.GetLTK()
	var K *big.Int
	if KBzs != nil {
		K = new(big.Int).SetBytes(KBzs)
	}
	GBzs := m.GetLTG()
	var G *big.Int
	if GBzs != nil {
		G = new(big.Int).SetBytes(GBzs)
	}
	KNonceBzs := m.GetLTKNonce()
	var KNonce *big.Int
	if KNonceBzs != nil {
		KNonce = new(big.Int).SetBytes(KNonceBzs)
	}
	GNonceBzs := m.GetLTGNonce()
	var GNonce *big.Int
	if GNonceBzs != nil {
		GNonce = new(big.Int).SetBytes(GNonceBzs)
	}

	GammaShareBzs := m.GetLTGammaShare()
	var GammaShare *big.Int
	if GammaShareBzs != nil {
		GammaShare = new(big.Int).SetBytes(GammaShareBzs)
	}
	DeltaShareBetasBzs := m.GetLTDeltaShareBetas()
	DeltaShareBetas := make([]*big.Int, len(DeltaShareBetasBzs))
	for i := range DeltaShareBetas {
		Bzs := DeltaShareBetasBzs[i]
		if Bzs != nil {
			DeltaShareBetas[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiShareBetasBzs := m.GetLTChiShareBetas()
	ChiShareBetas := make([]*big.Int, len(ChiShareBetasBzs))
	for i := range ChiShareBetas {
		Bzs := ChiShareBetasBzs[i]
		if Bzs != nil {
			ChiShareBetas[i] = new(big.Int).SetBytes(Bzs)
		}
	}

	BigGammaBzs := m.GetLTBigGamma()
	var BigGamma *crypto.ECPoint
	if BigGammaBzs != nil {
		item, err := crypto.NewECPointFromBytes(ec, BigGammaBzs)
		if err != nil {
			return nil, err
		}
		BigGamma = item
	}
	DeltaShareAlphasBzs := m.GetLTDeltaShareAlphas()
	DeltaShareAlphas := make([]*big.Int, len(DeltaShareAlphasBzs))
	for i := range DeltaShareAlphas {
		Bzs := DeltaShareAlphasBzs[i]
		if Bzs != nil {
			DeltaShareAlphas[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiShareAlphasBzs := m.GetLTChiShareAlphas()
	ChiShareAlphas := make([]*big.Int, len(ChiShareAlphasBzs))
	for i := range ChiShareAlphas {
		Bzs := ChiShareAlphasBzs[i]
		if Bzs != nil {
			ChiShareAlphas[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	DeltaShareBzs := m.GetLTDeltaShare()
	var DeltaShare *big.Int
	if DeltaShareBzs != nil {
		DeltaShare = new(big.Int).SetBytes(DeltaShareBzs)
	}
	ChiShareBzs := m.GetLTChiShare()
	var ChiShare *big.Int
	if ChiShareBzs != nil {
		ChiShare = new(big.Int).SetBytes(ChiShareBzs)
	}
	BigDeltaShareBzs := m.GetLTBigDeltaShare()
	var BigDeltaShare *crypto.ECPoint
	if BigDeltaShareBzs != nil {
		item, err := crypto.NewECPointFromBytes(ec, BigDeltaShareBzs)
		if err != nil {
			return nil, err
		}
		BigDeltaShare = item
	}

	BigRBzs := m.GetLTBigR()
	var BigR *crypto.ECPoint
	if BigRBzs != nil {
		item, err := crypto.NewECPointFromBytes(ec, BigRBzs)
		if err != nil {
			return nil, err
		}
		BigR = item
	}
	RxBzs := m.GetLTRx()
	var Rx *big.Int
	if RxBzs != nil {
		Rx = new(big.Int).SetBytes(RxBzs)
	}
	SigmaShareBzs := m.GetLTSigmaShare()
	var SigmaShare *big.Int
	if SigmaShareBzs != nil {
		SigmaShare = new(big.Int).SetBytes(SigmaShareBzs)
	}

	r1msgGBzs := m.GetLTr1MsgG()
	r1msgG := make([]*big.Int, len(r1msgGBzs))
	for i := range r1msgG {
		Bzs := r1msgGBzs[i]
		if Bzs != nil {
			r1msgG[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r1msgKBzs := m.GetLTr1MsgK()
	r1msgK := make([]*big.Int, len(r1msgKBzs))
	for i := range r1msgK {
		Bzs := r1msgKBzs[i]
		if Bzs != nil {
			r1msgK[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r1msgProofBzs := m.GetLTr1MsgProof()
	r1msgProof := make([]*zkpenc.ProofEnc, len(r1msgProofBzs)/zkpenc.ProofEncBytesParts)
	for i := range r1msgProof {
		if r1msgProofBzs[i*zkpenc.ProofEncBytesParts] != nil {
			item, err := zkpenc.NewProofFromBytes(r1msgProofBzs[(i * zkpenc.ProofEncBytesParts):(i*zkpenc.ProofEncBytesParts + zkpenc.ProofEncBytesParts)])
			if err != nil {
				return nil, err
			}
			r1msgProof[i] = item
		}
	}

	r2msgBigGammaShareBzs := m.GetLTr2MsgBigGammaShare()
	r2msgBigGammaShare := make([]*crypto.ECPoint, len(r2msgBigGammaShareBzs)/2)
	for i := range r2msgBigGammaShare {
		if r2msgBigGammaShareBzs[i*2] != nil {
			item, err := crypto.NewECPointFromBytes(ec, r2msgBigGammaShareBzs[(i*2):(i*2+2)])
			if err != nil {
				return nil, err
			}
			r2msgBigGammaShare[i] = item
		}
	}
	r2msgDeltaDBzs := m.GetLTr2MsgDeltaD()
	r2msgDeltaD := make([]*big.Int, len(r2msgDeltaDBzs))
	for i := range r2msgDeltaD {
		Bzs := r2msgDeltaDBzs[i]
		if Bzs != nil {
			r2msgDeltaD[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r2msgDeltaFBzs := m.GetLTr2MsgDeltaF()
	r2msgDeltaF := make([]*big.Int, len(r2msgDeltaFBzs))
	for i := range r2msgDeltaF {
		Bzs := r2msgDeltaFBzs[i]
		if Bzs != nil {
			r2msgDeltaF[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r2msgDeltaProofBzs := m.GetLTr2MsgDeltaProof()
	r2msgDeltaProof := make([]*zkpaffg.ProofAffg, len(r2msgDeltaProofBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range r2msgDeltaProof {
		if r2msgDeltaProofBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, r2msgDeltaProofBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err != nil {
				return nil, err
			}
			r2msgDeltaProof[i] = item
		}
	}
	r2msgChiDBzs := m.GetLTr2MsgChiD()
	r2msgChiD := make([]*big.Int, len(r2msgChiDBzs))
	for i := range r2msgChiD {
		Bzs := r2msgChiDBzs[i]
		if Bzs != nil {
			r2msgChiD[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r2msgChiFBzs := m.GetLTr2MsgChiF()
	r2msgChiF := make([]*big.Int, len(r2msgChiFBzs))
	for i := range r2msgChiF {
		Bzs := r2msgChiFBzs[i]
		if Bzs != nil {
			r2msgChiF[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r2msgChiProofBzs := m.GetLTr2MsgChiProof()
	r2msgChiProof := make([]*zkpaffg.ProofAffg, len(r2msgChiProofBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range r2msgDeltaProof {
		if r2msgChiProofBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, r2msgChiProofBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err != nil {
				return nil, err
			}
			r2msgChiProof[i] = item
		}
	}
	r2msgProofLogstarBzs := m.GetLTr2MsgProofLogstar()
	r2msgProofLogstar := make([]*zkplogstar.ProofLogstar, len(r2msgProofLogstarBzs)/zkplogstar.ProofLogstarBytesParts)
	for i := range r2msgProofLogstar {
		if r2msgProofLogstarBzs[i*zkplogstar.ProofLogstarBytesParts] != nil {
			item, err := zkplogstar.NewProofFromBytes(ec, r2msgProofLogstarBzs[(i*zkplogstar.ProofLogstarBytesParts):(i*zkplogstar.ProofLogstarBytesParts+zkplogstar.ProofLogstarBytesParts)])
			if err != nil {
				return nil, err
			}
			r2msgProofLogstar[i] = item
		}
	}

	r3msgDeltaShareBzs := m.GetLTr3MsgDeltaShare()
	r3msgDeltaShare := make([]*big.Int, len(r3msgDeltaShareBzs))
	for i := range r3msgDeltaShare {
		Bzs := r3msgDeltaShareBzs[i]
		if Bzs != nil {
			r3msgDeltaShare[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r3msgBigDeltaShareBzs := m.GetLTr3MsgBigDeltaShare()
	r3msgBigDeltaShare := make([]*crypto.ECPoint, len(r3msgBigDeltaShareBzs)/2)
	for i := range r3msgBigDeltaShare {
		if r3msgBigDeltaShareBzs[i*2] != nil {
			item, err := crypto.NewECPointFromBytes(ec, r3msgBigDeltaShareBzs[(i*2):(i*2+2)])
			if err != nil {
				return nil, err
			}
			r3msgBigDeltaShare[i] = item
		}
	}
	r3msgProofLogstarBzs := m.GetLTr3MsgProofLogstar()
	r3msgProofLogstar := make([]*zkplogstar.ProofLogstar, len(r3msgProofLogstarBzs)/zkplogstar.ProofLogstarBytesParts)
	for i := range r3msgProofLogstar {
		if r3msgProofLogstarBzs[i*zkplogstar.ProofLogstarBytesParts] != nil {
			item, err := zkplogstar.NewProofFromBytes(ec, r3msgProofLogstarBzs[(i*zkplogstar.ProofLogstarBytesParts):(i*zkplogstar.ProofLogstarBytesParts+zkplogstar.ProofLogstarBytesParts)])
			if err != nil {
				return nil, err
			}
			r3msgProofLogstar[i] = item
		}
	}

	r4msgSigmaShareBzs := m.GetLTr4MsgSigmaShare()
	r4msgSigmaShare := make([]*big.Int, len(r4msgSigmaShareBzs))
	for i := range r4msgSigmaShare {
		Bzs := r4msgSigmaShareBzs[i]
		if Bzs != nil {
			r4msgSigmaShare[i] = new(big.Int).SetBytes(Bzs)
		}
	}

	DeltaMtAFsBzs := m.GetLTDeltaMtAFs()
	DeltaMtAFs := make([]*big.Int, len(DeltaMtAFsBzs))
	for i := range DeltaMtAFs {
		Bzs := DeltaMtAFsBzs[i]
		if Bzs != nil {
			DeltaMtAFs[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	DeltaMtADsBzs := m.GetLTDeltaMtADs()
	DeltaMtADs := make([]*big.Int, len(DeltaMtADsBzs))
	for i := range DeltaMtADs {
		Bzs := DeltaMtADsBzs[i]
		if Bzs != nil {
			DeltaMtADs[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	DeltaMtADProofsBzs := m.GetLDDeltaMtADProofs()
	DeltaMtADProofs := make([]*zkpaffg.ProofAffg, len(DeltaMtADProofsBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range DeltaMtADProofs {
		if DeltaMtADProofsBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, DeltaMtADProofsBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err != nil {
				return nil, err
			}
			DeltaMtADProofs[i] = item
		}
	}
	ChiMtAFsBzs := m.GetLTChiMtAFs()
	ChiMtAFs := make([]*big.Int, len(ChiMtAFsBzs))
	for i := range ChiMtAFs {
		Bzs := ChiMtAFsBzs[i]
		if Bzs != nil {
			ChiMtAFs[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiMtADsBzs := m.GetLTChiMtADs()
	ChiMtADs := make([]*big.Int, len(ChiMtADsBzs))
	for i := range ChiMtADs {
		Bzs := ChiMtADsBzs[i]
		if Bzs != nil {
			ChiMtADs[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	ChiMtADProofsBzs := m.GetLTChiMtADProofs()
	ChiMtADProofs := make([]*zkpaffg.ProofAffg, len(ChiMtADProofsBzs)/zkpaffg.ProofAffgBytesParts)
	for i := range ChiMtADProofs {
		if ChiMtADProofsBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
			item, err := zkpaffg.NewProofFromBytes(ec, ChiMtADProofsBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
			if err != nil {
				return nil, err
			}
			ChiMtADProofs[i] = item
		}
	}

	r5msgHBzs := m.GetLTr5MsgH()
	r5msgH := make([]*big.Int, len(r5msgHBzs))
	for i := range r5msgH {
		Bzs := r5msgHBzs[i]
		if Bzs != nil {
			r5msgH[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r5msgProofMulBzs := m.GetLTr5MsgProofMul()
	r5msgProofMul := make([]*zkpmul.ProofMul, len(r5msgProofMulBzs)/zkpmul.ProofMulBytesParts)
	for i := range r5msgProofMul {
		if r5msgProofMulBzs[i*zkpmul.ProofMulBytesParts] != nil {
			item, err := zkpmul.NewProofFromBytes(r5msgProofMulBzs[(i * zkpmul.ProofMulBytesParts):(i*zkpmul.ProofMulBytesParts + zkpmul.ProofMulBytesParts)])
			if err != nil {
				return nil, err
			}
			r5msgProofMul[i] = item
		}
	}
	//r5msgDeltaShareEncBzs := m.GetLTr5MsgDeltaShareEnc()
	//r5msgDeltaShareEnc := make([]*big.Int, len(r5msgDeltaShareEncBzs))
	//for i := range r5msgDeltaShareEnc {
	//	Bzs := r5msgDeltaShareEncBzs[i]
	//	if Bzs != nil {
	//		r5msgDeltaShareEnc[i] = new(big.Int).SetBytes(Bzs)
	//	}
	//}
	r5msgProofDecBzs := m.GetLTr5MsgProofDec()
	r5msgProofDec := make([]*zkpdec.ProofDec, len(r5msgProofDecBzs)/zkpdec.ProofDecBytesParts)
	for i := range r5msgProofDec {
		if r5msgProofDecBzs[i*zkpdec.ProofDecBytesParts] != nil {
			item, err := zkpdec.NewProofFromBytes(r5msgProofDecBzs[(i * zkpdec.ProofDecBytesParts):(i*zkpdec.ProofDecBytesParts + zkpdec.ProofDecBytesParts)])
			if err != nil {
				return nil, err
			}
			r5msgProofDec[i] = item
		}
	}
	length := len(r5msgH) // Notice, using this length
	r5msgDjisBzs := m.GetLTr5MsgDjis()
	r5msgDjis := make([][]*big.Int, length)
	for j := 0; j < length; j++ {
		r5msgDjis[j] = make([]*big.Int, length)
	}
	for i, row := range r5msgDjis {
		for j := range row {
			Bzs := r5msgDjisBzs[i*length+j]
			if Bzs != nil {
				r5msgDjis[i][j] = new(big.Int).SetBytes(Bzs)
			}
		}
	}
	r5msgFjisBzs := m.GetLTr5MsgFjis()
	r5msgFjis := make([][]*big.Int, length)
	for j := 0; j < length; j++ {
		r5msgFjis[j] = make([]*big.Int, length)
	}
	for i, row := range r5msgFjis {
		for j := range row {
			Bzs := r5msgFjisBzs[i*length+j]
			if Bzs != nil {
				r5msgFjis[i][j] = new(big.Int).SetBytes(Bzs)
			}
		}
	}
	//r5msgQ3EncBzs := m.GetLTr5MsgQ3Enc()
	//r5msgQ3Enc := make([]*big.Int, len(r5msgQ3EncBzs))
	//for i := range r5msgQ3Enc {
	//	Bzs := r5msgQ3EncBzs[i]
	//	if Bzs != nil {
	//		r5msgQ3Enc[i] = new(big.Int).SetBytes(Bzs)
	//	}
	//}

	LocalTemp := &localTempData{
		ssid:   ssid,
		w:      w,
		BigWs:  BigWs,
		KShare: KShare,

		BigGammaShare: BigGammaShare,
		K:             K,
		G:             G,
		KNonce:        KNonce,
		GNonce:        GNonce,

		GammaShare:      GammaShare,
		DeltaShareBetas: DeltaShareBetas,
		ChiShareBetas:   ChiShareBetas,

		BigGamma:         BigGamma,
		DeltaShareAlphas: DeltaShareAlphas,
		ChiShareAlphas:   ChiShareAlphas,
		DeltaShare:       DeltaShare,
		ChiShare:         ChiShare,
		BigDeltaShare:    BigDeltaShare,

		BigR:       BigR,
		Rx:         Rx,
		SigmaShare: SigmaShare,

		r1msgG:     r1msgG,
		r1msgK:     r1msgK,
		r1msgProof: r1msgProof,

		r2msgBigGammaShare: r2msgBigGammaShare,
		r2msgDeltaD:        r2msgDeltaD,
		r2msgDeltaF:        r2msgDeltaF,
		r2msgDeltaProof:    r2msgDeltaProof,
		r2msgChiD:          r2msgChiD,
		r2msgChiF:          r2msgChiF,
		r2msgChiProof:      r2msgChiProof,
		r2msgProofLogstar:  r2msgProofLogstar,

		r3msgDeltaShare:    r3msgDeltaShare,
		r3msgBigDeltaShare: r3msgBigDeltaShare,
		r3msgProofLogstar:  r3msgProofLogstar,

		r4msgSigmaShare: r4msgSigmaShare,

		DeltaMtAFs:      DeltaMtAFs,
		DeltaMtADs:      DeltaMtADs,
		DeltaMtADProofs: DeltaMtADProofs,
		ChiMtAFs:        ChiMtAFs,
		ChiMtADs:        ChiMtADs,
		ChiMtADProofs:   ChiMtADProofs,
		r5msgH:          r5msgH,
		r5msgProofMul:   r5msgProofMul,
		//r5msgDeltaShareEnc: r5msgDeltaShareEnc,
		r5msgProofDec: r5msgProofDec,
		r5msgDjis:     r5msgDjis,
		r5msgFjis:     r5msgFjis,
		//r5msgQ3Enc:         r5msgQ3Enc,
	}

	return LocalTemp, nil
}
