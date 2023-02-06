// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		//	(*SignRound2Message)(nil),
	}
)

// ----- //

func NewSignRound1Message(
	from *tss.PartyID,
	signature *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		Signature: signature.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m.Signature != nil &&
		common.NonEmptyBytes(m.GetSignature())
}

func (m *SignRound1Message) UnmarshalSignature() *big.Int {
	return new(big.Int).SetBytes(m.GetSignature())
}

func (m *SignRound1Message) RoundNumber() int {
	return 1
}

func NewSignRound2Message(
	from *tss.PartyID,
	sign *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound2Message{
		Signature: sign.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m.Signature != nil &&
		common.NonEmptyBytes(m.GetSignature())
}

func (m *SignRound2Message) RoundNumber() int {
	return 2
}
