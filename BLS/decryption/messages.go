// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into schnorr-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DecryptionRound1Message)(nil),
		//	(*SignRound2Message)(nil),
	}
)

// ----- //

func NewDecryptionRound1Message(
	from *tss.PartyID,
	cipher *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &DecryptionRound1Message{
		CipherText: cipher.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DecryptionRound1Message) ValidateBasic() bool {
	return m.CipherText != nil &&
		common.NonEmptyBytes(m.GetCipherText())
}

func (m *DecryptionRound1Message) RoundNumber() int {
	return 1
}
