// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package derivekey

import (
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj []*crypto.ECPoint // Xj

		// used for test assertions (maybe discarded)
		PubKey *crypto.ECPoint // y

		// used for ecdsa and eddsa backward compatibility
		ECDSAPub *crypto.ECPoint
		EDDSAPub *crypto.ECPoint
	}

	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys LocalPartySaveData
		temp localTempData
		data common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *DeriveKeyResultMessage
	}

	localMessageStore struct {
		derivekeyRound1Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// child key index
		index []byte
		// parent chain code
		pChainCode []byte
		cChainCode []byte

		// temp data
		bssid *big.Int
		wi    *big.Int
		bigWs []*crypto.ECPoint

		pointHi *crypto.ECPoint
		pointVi *crypto.ECPoint
	}
)

func NewLocalParty(
	index []byte,
	chainCode []byte,
	params *tss.Parameters,
	key LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *DeriveKeyResultMessage,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.derivekeyRound1Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.index = index
	p.temp.pChainCode = chainCode
	return p
}

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	return
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalSecrets = sourceData.LocalSecrets

	newData.PubKey = sourceData.PubKey
	if sourceData.ECDSAPub != nil {
		newData.PubKey = sourceData.ECDSAPub
	}

	if sourceData.EDDSAPub != nil {
		newData.PubKey = sourceData.EDDSAPub
	}

	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic(errors.New("BuildLocalSaveDataSubset: unable to find a signer party in the local save data"))
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
	}
	return newData
}

func CalcChildVaultPrivateKey(curve elliptic.Curve, parentPrivateKey *big.Int, index, parentChainCode []byte) (childPrivateKey *big.Int, childChainCode []byte, err error) {
	hashToCurve, err := getHashToCurveInstance(curve)
	if err != nil {
		return nil, nil, err
	}
	wPath, err := getPathString(curve, "TBD", parentChainCode, index)
	if err != nil {
		return nil, nil, err
	}

	pointHi, err := getH2CPoint(curve, hashToCurve, wPath)
	if err != nil {
		return nil, nil, err
	}
	pointV := pointHi.ScalarMult(parentPrivateKey)

	hmac512 := hmac.New(sha512.New, parentChainCode)
	hmac512.Write(pointV.X().Bytes())
	ilr := hmac512.Sum(nil)
	ilNum := new(big.Int).SetBytes(ilr[:32])
	qBytesLen := (curve.Params().N.BitLen() >> 3) + 1
	for ilNum.Cmp(curve.Params().N) != -1 {
		ilNumAdd := new(big.Int).Add(ilNum, big.NewInt(1))
		reSampleBytes := sha512.Sum512(append([]byte("ResampleIlNumInDeriveKey"), ilNumAdd.Bytes()...))
		ilNum = new(big.Int).SetBytes(reSampleBytes[:qBytesLen])
	}
	childPrivateKey = new(big.Int).Mod(new(big.Int).Add(parentPrivateKey, ilNum), curve.Params().N)
	childChainCode = ilr[32:]

	return childPrivateKey, childChainCode, nil
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start(ctx context.Context) *tss.Error {
	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	return tss.BaseStart(ctx, p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(ctx context.Context, msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(ctx, p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(ctx context.Context, wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(ctx, msg)
}

func (p *LocalParty) StoreMessage(ctx context.Context, msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *DeriveKeyRound1Message:
		p.temp.derivekeyRound1Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		log.Warn(ctx, "unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
