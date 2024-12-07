// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

type (
	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		SkSigShare *big.Int
		RSigShare  *big.Int
		ShareID    *big.Int // xi, kj
	}

	// LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys
		PkSigShares []*crypto.ECPoint
		PrSigShares []*crypto.ECPoint

		// used for test assertions (may be discarded)
		PkSig   *crypto.ECPoint
		PrSig   *crypto.ECPoint
		Address *crypto.ECPoint
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.PkSigShares = make([]*crypto.ECPoint, partyCount)
	saveData.PrSigShares = make([]*crypto.ECPoint, partyCount)
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
	newData.PkSig = sourceData.PkSig
	newData.PrSig = sourceData.PrSig
	newData.Address = sourceData.Address
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic(errors.New("BuildLocalSaveDataSubset: unable to find a signer party in the local save data"))
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.PkSigShares[j] = sourceData.PkSigShares[savedIdx]
		newData.PrSigShares[j] = sourceData.PrSigShares[savedIdx]
	}
	return newData
}
