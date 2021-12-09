// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpmul "github.com/binance-chain/tss-lib/crypto/zkp/mul"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRoundMessage)(nil),
		(*IdentificationRoundMessage)(nil),
	}
)

func NewSignRoundMessage(
	from *tss.PartyID,
	Rx *big.Int,
	Ry *big.Int,
	SigmaShare *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRoundMessage{
		Rx: Rx.Bytes(),
		Ry: Ry.Bytes(),
		SigmaShare: SigmaShare.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRoundMessage) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SigmaShare)
}

func (m *SignRoundMessage) UnmarshalSigmaShare() *big.Int {
	return new(big.Int).SetBytes(m.GetSigmaShare())
}

// ----- //

func NewIdentificationRoundMessage(
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
	content := &IdentificationRoundMessage{
		H:             H.Bytes(),
		MulProof:      MulProofBzs[:],
		DeltaShareEnc: DeltaShareEnc.Bytes(),
		DecProof:      DecProofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationRoundMessage) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.H) &&
		common.NonEmptyBytes(m.DeltaShareEnc) &&
		common.NonEmptyMultiBytes(m.MulProof, zkpmul.ProofMulBytesParts) &&
		common.NonEmptyMultiBytes(m.DecProof, zkpdec.ProofDecBytesParts)
}

func (m *IdentificationRoundMessage) UnmarshalH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *IdentificationRoundMessage) UnmarshalDeltaShareEnc() *big.Int {
	return new(big.Int).SetBytes(m.GetDeltaShareEnc())
}

func (m *IdentificationRoundMessage) UnmarshalProofMul() (*zkpmul.ProofMul, error) {
	return zkpmul.NewProofFromBytes(m.GetMulProof())
}

func (m *IdentificationRoundMessage) UnmarshalProofDec() (*zkpdec.ProofDec, error) {
	return zkpdec.NewProofFromBytes(m.GetDecProof())
}
