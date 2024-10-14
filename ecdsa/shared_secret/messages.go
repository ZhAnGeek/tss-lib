// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package shared_secret

import (
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	zkpeqlog "github.com/Safulet/tss-lib-private/v2/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SharedSecretRound1Message)(nil),
	}
)

func NewSharedSecretRound1Message(
	from *tss.PartyID,
	AiB *crypto.ECPoint,
	Proof *zkpeqlog.ProofEqLog,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	bzs := AiB.Bytes()
	proofBzs := Proof.Bytes()
	content := &SharedSecretRound1Message{
		AiB:     bzs[:],
		EqProof: proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SharedSecretRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.AiB, 2) &&
		common.NonEmptyMultiBytes(m.EqProof, zkpeqlog.ProofEqLogBytesParts)
}

func (m *SharedSecretRound1Message) RoundNumber() int {
	return 1
}

func (m *SharedSecretRound1Message) UnmarshalAiB() (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(tss.S256(), m.GetAiB())
}

func (m *SharedSecretRound1Message) UnmarshalProof() (*zkpeqlog.ProofEqLog, error) {
	return zkpeqlog.NewProofFromBytes(m.GetEqProof())
}
