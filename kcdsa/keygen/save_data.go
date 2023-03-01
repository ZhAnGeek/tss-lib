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

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
	"github.com/Safulet/tss-lib-private/tss"
)

type (
	LocalPreParams struct {
		PaillierSK *paillier.PrivateKey // ski
		NTildei,
		H1i, H2i,
		Alpha, Beta,
		P, Q *big.Int
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets
		LocalPreParams

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj []*crypto.ECPoint // Xj

		// used for test assertions (may be discarded)
		PubKey *crypto.ECPoint // x ^-1 * G

		// used for test assertions (may be discarded)
		PubKeySchnorr *crypto.ECPoint // y

		BigR *crypto.ECPoint

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int

		PaillierPKs []*paillier.PublicKey // pkj
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	saveData.H1j = make([]*big.Int, partyCount)
	saveData.H2j = make([]*big.Int, partyCount)
	saveData.NTildej = make([]*big.Int, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)

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
	newData.LocalPreParams = sourceData.LocalPreParams
	newData.PubKey = sourceData.PubKey
	newData.BigR = sourceData.BigR
	newData.PubKeySchnorr = sourceData.PubKeySchnorr
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic(errors.New("BuildLocalSaveDataSubset: unable to find a signer party in the local save data"))
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
		newData.H1j[j] = sourceData.H1j[savedIdx]
		newData.H2j[j] = sourceData.H2j[savedIdx]
		newData.NTildej[j] = sourceData.NTildej[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]

	}
	return newData
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}
