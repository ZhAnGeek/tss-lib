// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

package derivekey

import (
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	zkpeqlog "github.com/Safulet/tss-lib-private/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/tss"
)

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DeriveKeyRound1Message)(nil),
	}
)

// ----- //

func NewDeriveKeyRound1Message(
	from *tss.PartyID,
	bssid *big.Int,
	partialEvalX *big.Int,
	partialEvalY *big.Int,
	proof *zkpeqlog.ProofEqLog,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	proofBzs := proof.Bytes()
	content := &DeriveKeyRound1Message{
		Bssid:        bssid.Bytes(),
		PartialEvalX: partialEvalX.Bytes(),
		PartialEvalY: partialEvalY.Bytes(),
		Proof:        proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DeriveKeyRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetBssid()) &&
		common.NonEmptyBytes(m.GetPartialEvalX()) &&
		common.NonEmptyBytes(m.GetPartialEvalY()) &&
		common.NonEmptyMultiBytes(m.GetProof(), 2)
}

func (m *DeriveKeyRound1Message) RoundNumber() int {
	return 1
}

func (m *DeriveKeyRound1Message) UnmarshalSsid() *big.Int {
	return new(big.Int).SetBytes(m.GetBssid())
}

func (m *DeriveKeyRound1Message) UnmarshalPartialEval(ec elliptic.Curve) (*crypto.ECPoint, error) {
	evalX := new(big.Int).SetBytes(m.GetPartialEvalX())
	evalY := new(big.Int).SetBytes(m.GetPartialEvalY())
	eval, err := crypto.NewECPoint(ec, evalX, evalY)
	return eval, err
}

func (m *DeriveKeyRound1Message) UnmarshalProof() (*zkpeqlog.ProofEqLog, error) {
	pfBzs := m.GetProof()
	return zkpeqlog.NewProofFromBytes(pfBzs)
}

func (m *DeriveKeyResultMessage) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetBssid()) &&
		common.NonEmptyBytes(m.GetParentChainCode()) &&
		common.NonEmptyBytes(m.GetIndex()) &&
		common.NonEmptyBytes(m.GetDelta()) &&
		common.NonEmptyBytes(m.GetChildChainCode())
}

func (m *DeriveKeyResultMessage) RoundNumber() int {
	return 2
}
