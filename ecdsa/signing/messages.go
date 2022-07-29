// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpmulstar "github.com/binance-chain/tss-lib/crypto/zkp/mulstar"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*IdentificationRound1Message)(nil),
	}
)

func NewSignRound1Message(
	from *tss.PartyID,
	SigmaShare *big.Int,
	Rx *big.Int,
	Ry *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		SigmaShare: SigmaShare.Bytes(),
		Rx:         Rx.Bytes(),
		Ry:         Ry.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SigmaShare) &&
		common.NonEmptyBytes(m.Rx) &&
		common.NonEmptyBytes(m.Ry)
}

func (m *SignRound1Message) RoundNumber() int {
	return 1
}

func (m *SignRound1Message) UnmarshalSigmaShare() *big.Int {
	return new(big.Int).SetBytes(m.GetSigmaShare())
}

func (m *SignRound1Message) UnmarshalRx() *big.Int {
	return new(big.Int).SetBytes(m.GetRx())
}

func (m *SignRound1Message) UnmarshalRy() *big.Int {
	return new(big.Int).SetBytes(m.GetRy())
}

// ----- //

func NewIdentificationRound1Message(
	to, from *tss.PartyID,
	H *big.Int,
	MulProof *zkpmulstar.ProofMulstar,
	Djis []*big.Int,
	Fjis []*big.Int,
	DecProof *zkpdec.ProofDec,
	Q3Enc *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
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
	DecProofBzs := DecProof.Bytes()
	// DjiProofsBzs := make([][]byte, len(DjiProofs)*zkpaffg.ProofAffgBytesParts)
	// for i, item := range DjiProofs {
	// 	if item != nil {
	// 		itemBzs := item.Bytes()
	// 		for j := 0; j < zkpaffg.ProofAffgBytesParts; j++ {
	// 			DjiProofsBzs[i*zkpenc.ProofEncBytesParts+j] = itemBzs[j]
	// 		}
	// 	}
	// }
	content := &IdentificationRound1Message{
		H:        H.Bytes(),
		MulProof: MulProofBzs[:],
		Djis:     DjisBzs,
		Fjis:     FjisBzs,
		// DjiProofs: DjiProofsBzs,
		DecProof: DecProofBzs[:],
		Q3Enc:    Q3Enc.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.H) &&
		common.NonEmptyMultiBytes(m.MulProof, zkpmulstar.ProofMulstarBytesParts) &&
		common.NonEmptyMultiBytes(m.Djis) &&
		common.NonEmptyMultiBytes(m.Fjis) &&
		common.NonEmptyBytes(m.Q3Enc) &&
		common.NonEmptyMultiBytes(m.DecProof, zkpdec.ProofDecBytesParts)
}

func (m *IdentificationRound1Message) RoundNumber() int {
	return 3
}

func (m *IdentificationRound1Message) UnmarshalH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *IdentificationRound1Message) UnmarshalProofMul() (*zkpmulstar.ProofMulstar, error) {
	return zkpmulstar.NewProofFromBytes(m.GetMulProof())
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

// func (m *IdentificationRound1Message) UnmarshalDjiProofs(ec elliptic.Curve) []*zkpaffg.ProofAffg {
// 	DjiProofsBzs := m.GetDjiProofs()
// 	DjiProofs := make([]*zkpaffg.ProofAffg, len(DjiProofsBzs)/zkpaffg.ProofAffgBytesParts)
// 	for i := range DjiProofs {
// 		if DjiProofsBzs[i*zkpaffg.ProofAffgBytesParts] != nil {
// 			item, err := zkpaffg.NewProofFromBytes(ec, DjiProofsBzs[(i*zkpaffg.ProofAffgBytesParts):(i*zkpaffg.ProofAffgBytesParts+zkpaffg.ProofAffgBytesParts)])
// 			if err == nil { // continue if error occurs
// 				DjiProofs[i] = item
// 			}
// 		}
// 	}
// 	return DjiProofs
// }

func (m *IdentificationRound1Message) UnmarshalProofDec() (*zkpdec.ProofDec, error) {
	return zkpdec.NewProofFromBytes(m.GetDecProof())
}

func (m *IdentificationRound1Message) UnmarshalQ3Enc() *big.Int {
	return new(big.Int).SetBytes(m.GetQ3Enc())
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
	var mBzs []byte
	if LocalTemp.m != nil {
		mBzs = LocalTemp.m.Bytes()
	}
	var KeyDerivationDeltaBzs []byte
	if LocalTemp.KeyDerivationDelta != nil {
		KeyDerivationDeltaBzs = LocalTemp.KeyDerivationDelta.Bytes()
	}

	var KShareBzs []byte
	if LocalTemp.KShare != nil {
		KShareBzs = LocalTemp.KShare.Bytes()
	}
	var ChiShareBzs []byte
	if LocalTemp.ChiShare != nil {
		ChiShareBzs = LocalTemp.ChiShare.Bytes()
	}
	var BigRBzs [][]byte
	if LocalTemp.BigR != nil {
		Bzs := LocalTemp.BigR.Bytes()
		BigRBzs = Bzs[:]
	}

	var SigmaShareBzs []byte
	if LocalTemp.SigmaShare != nil {
		SigmaShareBzs = LocalTemp.SigmaShare.Bytes()
	}

	var KBzs []byte
	if LocalTemp.K != nil {
		KBzs = LocalTemp.K.Bytes()
	}
	r1msgKBzs := make([][]byte, len(LocalTemp.R1msgK))
	for i, item := range LocalTemp.R1msgK {
		if item != nil {
			r1msgKBzs[i] = item.Bytes()
		}
	}
	ChiShareAlphasBzs := make([][]byte, len(LocalTemp.ChiShareAlphas))
	for i, item := range LocalTemp.ChiShareAlphas {
		if item != nil {
			ChiShareAlphasBzs[i] = item.Bytes()
		}
	}
	ChiShareBetasBzs := make([][]byte, len(LocalTemp.ChiShareBetas))
	for i, item := range LocalTemp.ChiShareBetas {
		if item != nil {
			ChiShareBetasBzs[i] = item.Bytes()
		}
	}
	r2msgChiDBzs := make([][]byte, len(LocalTemp.R2msgChiD))
	for i, item := range LocalTemp.R2msgChiD {
		if item != nil {
			r2msgChiDBzs[i] = item.Bytes()
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

	r4msgSigmaShareBzs := make([][]byte, len(LocalTemp.R4msgSigmaShare))
	for i, item := range LocalTemp.R4msgSigmaShare {
		if item != nil {
			r4msgSigmaShareBzs[i] = item.Bytes()
		}
	}

	r5msgHBzs := make([][]byte, len(LocalTemp.R5msgH))
	for i, item := range LocalTemp.R5msgH {
		if item != nil {
			r5msgHBzs[i] = item.Bytes()
		}
	}
	r5msgProofMulstarBzs := make([][]byte, len(LocalTemp.R5msgProofMulstar)*zkpmulstar.ProofMulstarBytesParts)
	for i, item := range LocalTemp.R5msgProofMulstar {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpmulstar.ProofMulstarBytesParts; j++ {
				r5msgProofMulstarBzs[i*zkpmulstar.ProofMulstarBytesParts+j] = itemBzs[j]
			}
		}
	}
	r5msgProofDecBzs := make([][]byte, len(LocalTemp.R5msgProofDec)*zkpdec.ProofDecBytesParts)
	for i, item := range LocalTemp.R5msgProofDec {
		if item != nil {
			itemBzs := item.Bytes()
			for j := 0; j < zkpdec.ProofDecBytesParts; j++ {
				r5msgProofDecBzs[i*zkpdec.ProofDecBytesParts+j] = itemBzs[j]
			}
		}
	}
	r5msgDjiLen := len(LocalTemp.R5msgDjis)
	r5msgDjisBzs := make([][]byte, r5msgDjiLen*r5msgDjiLen)
	for i, row := range LocalTemp.R5msgDjis {
		for j, item := range row {
			if item != nil {
				r5msgDjisBzs[i*r5msgDjiLen+j] = item.Bytes()
			}
		}
	}
	r5msgFjiLen := len(LocalTemp.R5msgFjis)
	r5msgFjisBzs := make([][]byte, r5msgFjiLen*r5msgFjiLen)
	for i, row := range LocalTemp.R5msgFjis {
		for j, item := range row {
			if item != nil {
				r5msgFjisBzs[i*r5msgFjiLen+j] = item.Bytes()
			}
		}
	}

	content := &LocalDumpPB{
		Index:    int32(Index),
		RoundNum: int32(RoundNum),

		LTw:                  wBzs,
		LTBigWs:              BigWsBzs,
		LTm:                  mBzs,
		LTKeyDerivationDelta: KeyDerivationDeltaBzs,

		LTssid:     LocalTemp.ssid,
		LTKShare:   KShareBzs,
		LTChiShare: ChiShareBzs,
		LTBigR:     BigRBzs,

		LTSigmaShare: SigmaShareBzs,

		LTK:              KBzs,
		LTr1MsgK:         r1msgKBzs,
		LTChiShareAlphas: ChiShareAlphasBzs,
		LTChiShareBetas:  ChiShareBetasBzs,
		LTr2MsgChiD:      r2msgChiDBzs,

		LTChiMtAFs:      ChiMtAFsBzs,
		LTChiMtADs:      ChiMtADsBzs,
		LTChiMtADProofs: ChiMtaDProofsBzs,

		LTr4MsgSigmaShare: r4msgSigmaShareBzs,

		LTr5MsgH:            r5msgHBzs,
		LTr5MsgProofMulstar: r5msgProofMulstarBzs,
		LTr5MsgProofDec:     r5msgProofDecBzs,
		LTr5MsgDjis:         r5msgDjisBzs,
		LTr5MsgFjis:         r5msgFjisBzs,
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
	msgBzs := m.GetLTm()
	var msg *big.Int
	if msgBzs != nil {
		msg = new(big.Int).SetBytes(msgBzs)
	}
	keyDerivationDeltaBzs := m.GetLTKeyDerivationDelta()
	var keyDerivationDelta *big.Int
	if keyDerivationDeltaBzs != nil {
		keyDerivationDelta = new(big.Int).SetBytes(keyDerivationDeltaBzs)
	}

	ssid := m.GetLTssid()
	KShareBzs := m.GetLTKShare()
	var KShare *big.Int
	if KShareBzs != nil {
		KShare = new(big.Int).SetBytes(KShareBzs)
	}
	ChiShareBzs := m.GetLTChiShare()
	var ChiShare *big.Int
	if ChiShareBzs != nil {
		ChiShare = new(big.Int).SetBytes(ChiShareBzs)
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

	SigmaShareBzs := m.GetLTSigmaShare()
	var SigmaShare *big.Int
	if SigmaShareBzs != nil {
		SigmaShare = new(big.Int).SetBytes(SigmaShareBzs)
	}
	r4msgSigmaShareBzs := m.GetLTr4MsgSigmaShare()
	r4msgSigmaShare := make([]*big.Int, len(r4msgSigmaShareBzs))
	for i := range r4msgSigmaShare {
		Bzs := r4msgSigmaShareBzs[i]
		if Bzs != nil {
			r4msgSigmaShare[i] = new(big.Int).SetBytes(Bzs)
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
	r5msgProofMulstarBzs := m.GetLTr5MsgProofMulstar()
	r5msgProofMulstar := make([]*zkpmulstar.ProofMulstar, len(r5msgProofMulstarBzs)/zkpmulstar.ProofMulstarBytesParts)
	for i := range r5msgProofMulstar {
		if r5msgProofMulstarBzs[i*zkpmulstar.ProofMulstarBytesParts] != nil {
			item, err := zkpmulstar.NewProofFromBytes(r5msgProofMulstarBzs[(i * zkpmulstar.ProofMulstarBytesParts):(i*zkpmulstar.ProofMulstarBytesParts + zkpmulstar.ProofMulstarBytesParts)])
			if err != nil {
				return nil, err
			}
			r5msgProofMulstar[i] = item
		}
	}
	// r5msgSigmaShareEncBzs := m.GetLTr5MsgSigmaShareEnc()
	// r5msgSigmaShareEnc := make([]*big.Int, len(r5msgSigmaShareEncBzs))
	// for i := range r5msgSigmaShareEnc {
	//	Bzs := r5msgSigmaShareEncBzs[i]
	//	if Bzs != nil {
	//		r5msgSigmaShareEnc[i] = new(big.Int).SetBytes(Bzs)
	//	}
	// }
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

	LocalTemp := &localTempData{
		w:                  w,
		BigWs:              BigWs,
		m:                  msg,
		KeyDerivationDelta: keyDerivationDelta,

		ssid:     ssid,
		KShare:   KShare,
		ChiShare: ChiShare,
		BigR:     BigR,

		SigmaShare:      SigmaShare,
		R4msgSigmaShare: r4msgSigmaShare,

		R5msgH:            r5msgH,
		R5msgProofMulstar: r5msgProofMulstar,
		R5msgProofDec:     r5msgProofDec,
		R5msgDjis:         r5msgDjis,
		R5msgFjis:         r5msgFjis,
	}

	return LocalTemp, nil
}
