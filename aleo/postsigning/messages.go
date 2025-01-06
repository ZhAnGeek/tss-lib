// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postsigning

import (
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*PSignRound1Message)(nil),
	}
)

// ----- //

func NewPSignRound1Message(
	from *tss.PartyID,
	zi *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &PSignRound1Message{
		ResponseShare: zi.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *PSignRound1Message) ValidateBasic() bool {
	return m != nil && m.ResponseShare != nil
}

func (m *PSignRound1Message) RoundNumber() int {
	return 1
}

func (m *PSignRound1Message) UnmarshalResponseShare() *big.Int {
	return new(big.Int).SetBytes(m.GetResponseShare())
}

func NewRequestData(
	challenge *big.Int,
	response *big.Int) *RequestData {
	content := &RequestData{
		Challenge: challenge.Bytes(),
		Response:  response.Bytes(),
	}
	return content
}

func (m *RequestData) UnmarshalChallenge() *big.Int {
	return new(big.Int).SetBytes(m.GetChallenge())
}

func (m *RequestData) UnmarshalResponse() *big.Int {
	return new(big.Int).SetBytes(m.GetResponse())
}
