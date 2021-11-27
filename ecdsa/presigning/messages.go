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
		(*IdentificationRound6Message)(nil),
	}
)

// ----- //
func NewPreSignData(
	index int,
	ssid []byte,
	bigR *crypto.ECPoint,
	kShare *big.Int,
	chiShare *big.Int,
) *PreSignatureData {
	bigRBzs := bigR.Bytes()
	content := &PreSignatureData{
		Index:    int32(index),
		Ssid:     ssid,
		BigR:     bigRBzs[:],
		KShare:   kShare.Bytes(),
		ChiShare: chiShare.Bytes(),
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

func NewIdentificationRound6Message(
	to, from *tss.PartyID,
	H *big.Int,
	MulProof *zkpmul.ProofMul,
	DeltaShareEnc *big.Int,
	DecProof *zkpdec.ProofDec,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	MulProofBzs := MulProof.Bytes()
	DecProofBzs := DecProof.Bytes()
	content := &IdentificationRound6Message{
		H:             H.Bytes(),
		MulProof:      MulProofBzs[:],
		DeltaShareEnc: DeltaShareEnc.Bytes(),
		DecProof:      DecProofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationRound6Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.H) &&
		common.NonEmptyBytes(m.DeltaShareEnc) &&
		common.NonEmptyMultiBytes(m.MulProof, zkpmul.ProofMulBytesParts) &&
		common.NonEmptyMultiBytes(m.DecProof, zkpdec.ProofDecBytesParts)
}

func (m *IdentificationRound6Message) UnmarshalH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *IdentificationRound6Message) UnmarshalDeltaShareEnc() *big.Int {
	return new(big.Int).SetBytes(m.GetDeltaShareEnc())
}

func (m *IdentificationRound6Message) UnmarshalProofMul() (*zkpmul.ProofMul, error) {
	return zkpmul.NewProofFromBytes(m.GetMulProof())
}

func (m *IdentificationRound6Message) UnmarshalProofDec() (*zkpdec.ProofDec, error) {
	return zkpdec.NewProofFromBytes(m.GetDecProof())
}

func NewLocalDumpPB(
	Index int,
	RoundNum int,
	LocalTemp *localTempData,
) *LocalDumpPB {
	//BigWs_flat, err := crypto.FlattenECPoints(LocalTemp.BigWs)
	//if err != nil {
	//	return nil
	//}
	//BigWsBzs := make([][]byte, len(BigWs_flat))
	//for i, item := range(BigWs_flat) {
	//	BigWsBzs[i] = item.Bytes()
	//}
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
	var keyDerivationDeltaBzs []byte
	if LocalTemp.keyDerivationDelta != nil {
		keyDerivationDeltaBzs = LocalTemp.keyDerivationDelta.Bytes()
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
	var DeltaMtAFBzs []byte
	if LocalTemp.DeltaMtAF != nil {
		DeltaMtAFBzs = LocalTemp.DeltaMtAF.Bytes()
	}
	var ChiMtAFBzs []byte
	if LocalTemp.ChiMtAF != nil {
		ChiMtAFBzs = LocalTemp.ChiMtAF.Bytes()
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

	r6msgHBzs := make([][]byte, len(LocalTemp.r6msgH))
	for i, item := range LocalTemp.r6msgH {
		if item != nil {
			r6msgHBzs[i] = item.Bytes()
		}
	}
	r6msgProofMulBzs := make([][]byte, len(LocalTemp.r6msgProofMul)*zkpmul.ProofMulBytesParts)
	for i, item := range LocalTemp.r6msgProofMul {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpmul.ProofMulBytesParts; j++ {
				r6msgProofMulBzs[i*zkpmul.ProofMulBytesParts+j] = itemBzs[j]
			}
		}
	}
	r6msgDeltaShareEncBzs := make([][]byte, len(LocalTemp.r6msgDeltaShareEnc))
	for i, item := range LocalTemp.r6msgDeltaShareEnc {
		if item != nil {
			r6msgDeltaShareEncBzs[i] = item.Bytes()
		}
	}
	r6msgProofDecBzs := make([][]byte, len(LocalTemp.r6msgProofDec)*zkpdec.ProofDecBytesParts)
	for i, item := range LocalTemp.r6msgProofDec {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpdec.ProofDecBytesParts; j++ {
				r6msgProofDecBzs[i*zkpdec.ProofDecBytesParts+j] = itemBzs[j]
			}
		}
	}

	content := &LocalDumpPB{
		Index:    int32(Index),
		RoundNum: int32(RoundNum),

		LTssid:   LocalTemp.ssid,
		LTw:      wBzs,
		LTBigWs:  BigWsBzs,
		LTKShare: KShareBzs,

		LTBigGammaShare:      BigGammaShareBzs,
		LTK:                  KBzs,
		LTG:                  GBzs,
		LTKNonce:             KNonceBzs,
		LTGNonce:             GNonceBzs,
		LTkeyDerivationDelta: keyDerivationDeltaBzs,

		LTGammaShare:      GammaShareBzs,
		LTDeltaShareBetas: DeltaShareBetasBzs,
		LTChiShareBetas:   ChiShareBetasBzs,
		LTDeltaMtAF:       DeltaMtAFBzs,
		LTChiMtAF:         ChiMtAFBzs,

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

		LTr6MsgH:             r6msgHBzs,
		LTr6MsgProofMul:      r6msgProofMulBzs,
		LTr6MsgDeltaShareEnc: r6msgDeltaShareEncBzs,
		LTr6MsgProofDec:      r6msgProofDecBzs,
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
	keyDerivationDeltaBzs := m.GetLTkeyDerivationDelta()
	var keyDerivationDelta *big.Int
	if keyDerivationDeltaBzs != nil {
		keyDerivationDelta = new(big.Int).SetBytes(keyDerivationDeltaBzs)
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
	DeltaMtAFBzs := m.GetLTDeltaMtAF()
	var DeltaMtAF *big.Int
	if DeltaMtAFBzs != nil {
		DeltaMtAF = new(big.Int).SetBytes(DeltaMtAFBzs)
	}
	ChiMtAFBzs := m.GetLTChiMtAF()
	var ChiMtAF *big.Int
	if ChiMtAFBzs != nil {
		ChiMtAF = new(big.Int).SetBytes(ChiMtAFBzs)
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

	r6msgHBzs := m.GetLTr6MsgH()
	r6msgH := make([]*big.Int, len(r6msgHBzs))
	for i := range r6msgH {
		Bzs := r6msgHBzs[i]
		if Bzs != nil {
			r6msgH[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r6msgProofMulBzs := m.GetLTr6MsgProofMul()
	r6msgProofMul := make([]*zkpmul.ProofMul, len(r6msgProofMulBzs)/zkpmul.ProofMulBytesParts)
	for i := range r6msgProofMul {
		if r6msgProofMulBzs[i*zkpmul.ProofMulBytesParts] != nil {
			item, err := zkpmul.NewProofFromBytes(r6msgProofMulBzs[(i * zkpmul.ProofMulBytesParts):(i*zkpmul.ProofMulBytesParts + zkpmul.ProofMulBytesParts)])
			if err != nil {
				return nil, err
			}
			r6msgProofMul[i] = item
		}
	}
	r6msgDeltaShareEncBzs := m.GetLTr6MsgDeltaShareEnc()
	r6msgDeltaShareEnc := make([]*big.Int, len(r6msgDeltaShareEncBzs))
	for i := range r6msgDeltaShareEnc {
		Bzs := r6msgDeltaShareEncBzs[i]
		if Bzs != nil {
			r6msgDeltaShareEnc[i] = new(big.Int).SetBytes(Bzs)
		}
	}
	r6msgProofDecBzs := m.GetLTr6MsgProofDec()
	r6msgProofDec := make([]*zkpdec.ProofDec, len(r6msgProofDecBzs)/zkpdec.ProofDecBytesParts)
	for i := range r6msgProofDec {
		if r6msgProofDecBzs[i*zkpdec.ProofDecBytesParts] != nil {
			item, err := zkpdec.NewProofFromBytes(r6msgProofDecBzs[(i * zkpdec.ProofDecBytesParts):(i*zkpdec.ProofDecBytesParts + zkpdec.ProofDecBytesParts)])
			if err != nil {
				return nil, err
			}
			r6msgProofDec[i] = item
		}
	}

	LocalTemp := &localTempData{
		ssid:   ssid,
		w:      w,
		BigWs:  BigWs,
		KShare: KShare,

		BigGammaShare:      BigGammaShare,
		K:                  K,
		G:                  G,
		KNonce:             KNonce,
		GNonce:             GNonce,
		keyDerivationDelta: keyDerivationDelta,

		GammaShare:      GammaShare,
		DeltaShareBetas: DeltaShareBetas,
		ChiShareBetas:   ChiShareBetas,
		DeltaMtAF:       DeltaMtAF,
		ChiMtAF:         ChiMtAF,

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

		r6msgH:             r6msgH,
		r6msgProofMul:      r6msgProofMul,
		r6msgDeltaShareEnc: r6msgDeltaShareEnc,
		r6msgProofDec:      r6msgProofDec,
	}

	return LocalTemp, nil
}
