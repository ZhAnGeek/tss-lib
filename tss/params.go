// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"time"
)

type (
	VersionInfo struct {
		RejectionSampleVersion RejectionSampleVersion
	}

	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		safePrimeGenTimeout time.Duration
		needsIdentifaction  bool
		nonce               int
		hashFunc            func() hash.Hash
		network             string
		version             *VersionInfo
		schnorr             bool
	}

	ReSharingParameters struct {
		*Parameters
		newParties    *PeerContext
		newPartyCount int
		newThreshold  int
		nonce         int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int, needsIdentification bool, nonce int, opts ...ConfigOpt) *Parameters {
	config := NewConfig()
	for _, opt := range opts {
		err := opt(config)
		if err != nil {
			panic(errors.New(fmt.Sprintf("Error happened when initial config %s", err.Error())))
		}
	}

	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		needsIdentifaction:  needsIdentification,
		safePrimeGenTimeout: config.SafePrimeTimeout,
		nonce:               nonce,
		version:             config.VersionInfo,
	}
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}

func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

func (params *Parameters) NeedsIdentifaction() bool {
	return params.needsIdentifaction
}

func (params *Parameters) Version() *VersionInfo {
	return params.version
}

func (params *Parameters) Nonce() int {
	return params.nonce
}

func (params *Parameters) SetHashFunc(hashFunc func() hash.Hash) {
	params.hashFunc = hashFunc
}

func (params *Parameters) SetIsSchnorr() {
	params.schnorr = true
}

func (params *Parameters) IsSchnorr() bool {
	return params.schnorr
}

func (params *Parameters) HashFunc() hash.Hash {
	if params.hashFunc == nil {
		return sha512.New()
	}
	return params.hashFunc()
}

func (params *Parameters) SetNetwork(network string) {
	params.network = network
}

func (params *Parameters) Network() string {
	return params.network
}

// ----- //

// Exported, used in `tss` client
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold, nonce int, opts ...ConfigOpt) *ReSharingParameters {
	params := NewParameters(ec, ctx, partyID, partyCount, threshold, false, nonce, opts...) // No identification in resharing
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}
}

func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReSharingParameters) OldPartyCount() int {
	return rgParams.partyCount
}

func (rgParams *ReSharingParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

func (rgParams *ReSharingParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

func (rgParams *ReSharingParameters) NewThreshold() int {
	return rgParams.newThreshold
}

func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.parties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}

func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.newParties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}
